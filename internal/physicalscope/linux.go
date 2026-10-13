//go:build linux

package physicalscope

import (
	"context"
	"encoding/binary"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"golang.org/x/sys/unix"
)

func platformSource(provider *netidentity.Provider, stock bool) observerSource {
	return platformSourceWithBindings(provider, stock, bindSelectedKernelNeighbors)
}

type kernelNeighborBinder func(context.Context, Selection, []Segment, map[byte][]message) ([]Device, error)

func platformSourceWithBindings(provider *netidentity.Provider, stock bool, bind kernelNeighborBinder) observerSource {
	return observerSource{
		current: func(ctx context.Context, use func(context.Context, netidentity.Identity) error) error {
			return provider.WithCurrent(ctx, func(c context.Context, id netidentity.Identity) error {
				if stock && id.Kind != netidentity.ReviewedSingleInitNet || !stock && id.Kind != netidentity.ProcNetInode {
					return at("source.identity.kind", nil)
				}
				return use(c, id)
			})
		},
		open: openFence,
		capture: func(ctx context.Context, selection Selection) ([]Segment, []Device, error) {
			var native []nativeSegment
			if stock {
				raw, err := provider.ReadReviewedStockInterfaces(ctx)
				if err != nil {
					return nil, nil, at("ndm.command", err)
				}
				native, err = parseNDM(raw)
				if err != nil {
					return nil, nil, at("ndm.text", err)
				}
			}
			return captureKernelWithBindings(ctx, selection, native, stock, bind)
		},
	}
}

func platformFiniteIPv4Source(provider *netidentity.Provider) observerSource {
	source := platformSourceWithBindings(provider, true, bindFiniteIPv4KernelNeighbors)
	open := source.open
	source.open = func(c context.Context) (lifecycleFence, error) {
		fence, err := open(c)
		if err != nil {
			return nil, err
		}
		f, ok := fence.(*kernelFence)
		if !ok {
			return nil, at("finite.fence.original", fence.close())
		}
		return &finiteIPv4KernelFence{original: f}, nil
	}
	return source
}

type finiteIPv4KernelFence struct{ original *kernelFence }

func (f *finiteIPv4KernelFence) check(c context.Context, snapshot Snapshot) error {
	return f.original.reader.checkFinite(c, snapshot)
}
func (f *finiteIPv4KernelFence) close() error { return f.original.close() }

const fenceGroups = 1 | 4 | 0x10 | 0x100 | 0x40 | 0x400 // LINK, NEIGH, IPv4/IPv6 address and route.
const maxNetBytes = 4 << 20

var requestSequence atomic.Uint32

func routeSocket(groups uint32) (int, uint32, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, 0, at("netlink.socket.open", err)
	}
	fail := func(stage string, err error) (int, uint32, error) { _ = unix.Close(fd); return -1, 0, at(stage, err) }
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 2<<20); err != nil {
		return fail("netlink.socket.receive-buffer", err)
	}
	// NETLINK_NO_ENOBUFS is deliberately never set. Loss breaks continuity.
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		return fail("netlink.socket.bind", err)
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return fail("netlink.socket.name", err)
	}
	bound, ok := address.(*unix.SockaddrNetlink)
	if !ok || bound.Pid == 0 || bound.Groups != groups {
		return fail("netlink.socket.binding", nil)
	}
	return fd, bound.Pid, nil
}
func receive(fd int, buf []byte) (int, error) {
	n, _, flags, from, err := unix.Recvmsg(fd, buf, nil, unix.MSG_DONTWAIT)
	if err != nil {
		return 0, err
	}
	sender, ok := from.(*unix.SockaddrNetlink)
	if !ok {
		return 0, at("netlink.receive.sender-type", nil)
	}
	if sender.Pid != 0 {
		return 0, at("netlink.receive.sender-port", nil)
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return 0, at("netlink.receive.truncated", nil)
	}
	if n <= 0 {
		return 0, at("netlink.receive.empty", nil)
	}
	return n, nil
}
func dump(ctx context.Context, kind uint16, family byte) ([]message, error) {
	fd, pid, err := routeSocket(0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	seq := requestSequence.Add(1)
	if seq == 0 {
		seq = requestSequence.Add(1)
	}
	bodySize := map[uint16]int{18: 16, 22: 8, 26: 12, 30: 12}[kind]
	if bodySize == 0 {
		return nil, ErrUnknown
	}
	request := make([]byte, 16+bodySize)
	binary.NativeEndian.PutUint32(request[:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], kind)
	binary.NativeEndian.PutUint16(request[6:8], 1|0x300)
	binary.NativeEndian.PutUint32(request[8:12], seq)
	binary.NativeEndian.PutUint32(request[12:16], pid)
	request[16] = family
	if err = unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	buf := make([]byte, 1<<20)
	total := 0
	out := []message{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := receive(fd, buf)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if _, err = unix.Poll(poll, 20); err != nil && err != unix.EINTR {
				return nil, err
			}
			if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				return nil, ErrUnknown
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		total += n
		if total > maxNetBytes {
			return nil, ErrUnknown
		}
		frames, err := messages(buf[:n])
		if err != nil {
			return nil, err
		}
		for i, m := range frames {
			if m.seq != seq || m.pid != pid || m.flags&^uint16(2) != 0 {
				return nil, ErrUnknown
			}
			if m.kind == 3 {
				if i != len(frames)-1 || len(m.data) != 4 || binary.NativeEndian.Uint32(m.data) != 0 {
					return nil, ErrUnknown
				}
				// Any unsolicited/trailing queued datagram invalidates closure.
				if _, err := receive(fd, buf); err != unix.EAGAIN && err != unix.EWOULDBLOCK {
					return nil, ErrUnknown
				}
				return out, nil
			}
			if m.kind != kind-2 || m.flags&2 == 0 || len(out) >= 8192 {
				return nil, ErrUnknown
			}
			m.data = slices.Clone(m.data)
			out = append(out, m)
		}
	}
}

type kernelFence struct {
	fd     int
	pid    uint32
	cookie uint64
	// Actual kernel readback; the requested SO_RCVBUF can be capped. It is
	// diagnostic metadata only, never proof that notification loss is impossible.
	receiveBuffer int
	reader        *originalFenceCollector
	closeOnce     sync.Once
	closeErr      error
}

func openFence(ctx context.Context) (lifecycleFence, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, at("fence.open.context", nil)
	}
	fd, pid, err := routeSocket(fenceGroups)
	if err != nil {
		return nil, boundary("fence.open.socket", err)
	}
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil || cookie == 0 {
		_ = unix.Close(fd)
		return nil, at("fence.cookie", err)
	}
	actualBuffer, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil || actualBuffer <= 0 {
		_ = unix.Close(fd)
		return nil, at("fence.receive-buffer.read", err)
	}
	f := &kernelFence{fd: fd, pid: pid, cookie: cookie, receiveBuffer: actualBuffer}
	f.reader = newOriginalFenceCollector(fenceCollectorSource{
		current: f.currentError,
		receive: func(buf []byte) (int, bool, error) {
			n, err := receive(f.fd, buf)
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				return 0, true, nil
			}
			if err == unix.ENOBUFS {
				return 0, false, boundary("fence.receive.loss", err)
			}
			if err != nil {
				return 0, false, boundary("fence.receive.read", err)
			}
			return n, false, nil
		},
		wait: func() error {
			poll := []unix.PollFd{{Fd: int32(f.fd), Events: unix.POLLIN}}
			if _, err := unix.Poll(poll, 20); err != nil && err != unix.EINTR {
				return boundary("fence.poll.read", err)
			}
			if poll[0].Revents&(unix.POLLHUP|unix.POLLNVAL) != 0 {
				return at("fence.poll.descriptor", nil)
			}
			// POLLERR wakes the sole reader, which must receive the actual
			// socket error (including ENOBUFS); it is never muted or cleared.
			return nil
		},
	})
	return f, nil
}
func (f *kernelFence) currentError() error {
	cookie, err := unix.GetsockoptUint64(f.fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		return at("fence.descriptor.cookie.read", err)
	}
	if cookie != f.cookie || cookie == 0 {
		return at("fence.descriptor.cookie.changed", nil)
	}
	address, err := unix.Getsockname(f.fd)
	if err != nil {
		return at("fence.descriptor.name", err)
	}
	bound, ok := address.(*unix.SockaddrNetlink)
	if !ok || bound.Family != unix.AF_NETLINK {
		return at("fence.descriptor.family", nil)
	}
	if bound.Pid != f.pid {
		return at("fence.descriptor.port", nil)
	}
	if bound.Groups != fenceGroups {
		return at("fence.descriptor.groups", nil)
	}
	return nil
}
func (f *kernelFence) close() error {
	f.closeOnce.Do(func() {
		f.reader.close() // Cancel and join before touching the descriptor.
		if err := f.currentError(); err != nil {
			f.closeErr = boundary("fence.close.descriptor", err)
			return // Never close a replaced descriptor.
		}
		f.closeErr = unix.Close(f.fd)
	})
	return f.closeErr
}
func (f *kernelFence) check(ctx context.Context, snapshot Snapshot) error {
	return f.reader.check(ctx, snapshot)
}

func captureKernel(ctx context.Context, selection Selection, native []nativeSegment, stock bool) ([]Segment, []Device, error) {
	return captureKernelWithBindings(ctx, selection, native, stock, bindSelectedKernelNeighbors)
}

func captureKernelWithBindings(ctx context.Context, selection Selection, native []nativeSegment, stock bool, bind kernelNeighborBinder) ([]Segment, []Device, error) {
	linkFrames, err := dump(ctx, 18, 0)
	if err != nil {
		return nil, nil, at("kernel.links", err)
	}
	addressFrames, err := dump(ctx, 22, 0)
	if err != nil {
		return nil, nil, at("kernel.addresses", err)
	}
	routeFrames := []message{}
	for _, family := range []byte{2, 10} {
		frames, err := dump(ctx, 26, family)
		if err != nil {
			return nil, nil, at("kernel.routes", err)
		}
		routeFrames = append(routeFrames, frames...)
	}
	segments, err := assembleSegments(selection, native, stock, linkFrames, addressFrames, routeFrames)
	if err != nil {
		return nil, nil, err // Retain the closed assembler branch; no raw data.
	}
	bindings, err := observeKernelBindingsWith(ctx, selection, segments, bind)
	if err != nil {
		return nil, nil, err // Retain the closed binding branch; no raw data.
	}
	return segments, bindings, nil
}
func observeKernelBindings(ctx context.Context, segments []Segment) ([]Device, error) {
	return observeSelectedKernelBindings(ctx, Selection{}, segments)
}
func observeSelectedKernelBindings(ctx context.Context, selection Selection, segments []Segment) ([]Device, error) {
	return observeKernelBindingsWith(ctx, selection, segments, bindSelectedKernelNeighbors)
}

func observeKernelBindingsWith(ctx context.Context, selection Selection, segments []Segment, bind kernelNeighborBinder) ([]Device, error) {
	families := map[byte][]message{}
	for _, family := range []byte{2, 10} {
		frames, err := dump(ctx, 30, family)
		if err != nil {
			if family == 2 {
				return nil, at("kernel.bindings.ipv4.dump", err)
			}
			return nil, at("kernel.bindings.ipv6.dump", err)
		}
		families[family] = frames
	}
	return bind(ctx, selection, segments, families)
}
