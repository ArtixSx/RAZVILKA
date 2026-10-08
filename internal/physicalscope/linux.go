//go:build linux

package physicalscope

import (
	"context"
	"encoding/binary"
	"slices"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"golang.org/x/sys/unix"
)

func platformSource(provider *netidentity.Provider, stock bool) observerSource {
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
			return captureKernel(ctx, selection, native, stock)
		},
	}
}

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
	closed bool
	failed bool
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
	return &kernelFence{fd: fd, pid: pid, cookie: cookie}, nil
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
	if f.closed {
		return nil
	}
	f.closed = true
	if err := f.currentError(); err != nil {
		return boundary("fence.close.descriptor", err)
	} // Never close a replaced descriptor.
	return unix.Close(f.fd)
}
func (f *kernelFence) check(ctx context.Context, segments []Segment, devices []Device) error {
	if f.closed {
		return at("fence.check.closed", nil)
	}
	if f.failed {
		return at("fence.check.failed", nil)
	}
	if ctx.Err() != nil {
		return boundary("fence.check.context", ctx.Err())
	}
	if err := f.currentError(); err != nil {
		return boundary("fence.check.descriptor", err)
	}
	buf := make([]byte, 1<<20)
	total := 0
	fail := func(stage string, err error) error { f.failed = true; return boundary(stage, err) }
	for {
		if ctx.Err() != nil {
			return fail("fence.drain.context", ctx.Err())
		}
		n, err := receive(f.fd, buf)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			if err := f.currentError(); err != nil {
				return fail("fence.drain.closing-descriptor", err)
			}
			return nil
		}
		if err != nil {
			if err == unix.ENOBUFS {
				return fail("fence.receive.loss", err)
			}
			return fail("fence.receive.read", err)
		}
		total += n
		if total > maxNetBytes {
			return fail("fence.receive.byte-limit", nil)
		}
		frames, err := messages(buf[:n])
		if err != nil {
			return fail("fence.datagram.decode", err)
		}
		if err := checkNotifications(frames, segments, devices); err != nil {
			return fail("fence.notifications", err)
		}
	}
}

func captureKernel(ctx context.Context, selection Selection, native []nativeSegment, stock bool) ([]Segment, []Device, error) {
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
	bindings, err := observeKernelBindings(ctx, segments)
	if err != nil {
		return nil, nil, err // Retain the closed binding branch; no raw data.
	}
	return segments, bindings, nil
}
func observeKernelBindings(ctx context.Context, segments []Segment) ([]Device, error) {
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
	return bindKernelNeighbors(ctx, segments, families)
}
