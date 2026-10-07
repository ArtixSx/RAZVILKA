//go:build linux

package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func backendInventorySystemPlatform() backendInventoryPlatform {
	return backendInventoryPlatform{endpoint: backendInventoryEndpoint, openNFT: openBackendNFTSocket}
}

func backendInventoryEndpoint(ctx context.Context) (backendInventoryScope, error) {
	var scope backendInventoryScope
	if err := ctx.Err(); err != nil {
		return scope, err
	}
	file, err := os.Open("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return scope, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 129))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > 128 {
		return scope, errors.Join(errBackendInventory, readErr, closeErr)
	}
	scope.BootID = strings.TrimSpace(string(data))
	// Confirm both the process and the actual calling thread namespace. No
	// setns occurs here; thread-self must not differ from the frozen process.
	scope.NetNamespace, err = os.Readlink("/proc/self/ns/net")
	if err != nil {
		return scope, err
	}
	thread, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil || thread != scope.NetNamespace || !nfqws2ManagedBoot(scope.BootID) || !nfqwsScopedNamespace(scope.NetNamespace) {
		return scope, errors.Join(errBackendInventory, err)
	}
	return scope, ctx.Err()
}

type backendNFTSocket struct {
	fd             int
	port, sequence uint32
	budget         backendNFTBudget
	closed         bool
}

// GET can trigger kernel request_module on some kernels. This is an observer
// with no explicit module/batch/mutation probe, not a claim of zero autoload.
func openBackendNFTSocket(ctx context.Context) (backendNFTSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var seed [4]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	seq := binary.NativeEndian.Uint32(seed[:])
	if seq == 0 || seq > ^uint32(0)-3 {
		seq = 1
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = unix.Close(fd)
		}
	}()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return nil, err
	}
	local, ok := address.(*unix.SockaddrNetlink)
	if !ok || local.Family != unix.AF_NETLINK || local.Pid == 0 || local.Groups != 0 {
		return nil, errBackendInventory
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	failed = false
	return &backendNFTSocket{fd: fd, port: local.Pid, sequence: seq}, nil
}

func (s *backendNFTSocket) Generation(ctx context.Context) (uint32, error) {
	d, err := s.exchange(ctx, backendNFTGetGen, 0)
	if err != nil {
		return 0, err
	}
	return d.generation, nil
}

func (s *backendNFTSocket) Tables(ctx context.Context, generation uint32) ([]backendNFTTable, error) {
	d, err := s.exchange(ctx, backendNFTGetTable, generation)
	if err != nil {
		return nil, err
	}
	return append([]backendNFTTable(nil), d.tables...), nil
}

func (s *backendNFTSocket) Close() error {
	if s == nil || s.closed {
		return errBackendInventory
	}
	s.closed = true
	return unix.Close(s.fd)
}

func (s *backendNFTSocket) exchange(ctx context.Context, kind uint16, generation uint32) (*backendNFTDecoder, error) {
	if ctx == nil || s == nil || s.closed || ctx.Err() != nil {
		return nil, errBackendInventory
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > backendInventoryTimeout {
		return nil, errBackendInventory
	}
	request, err := backendNFTRequest(kind, s.sequence, s.port)
	if err != nil {
		return nil, err
	}
	s.sequence++
	d, err := newBackendNFTDecoder(request, generation, &s.budget)
	if err != nil {
		return nil, err
	}
	// NONBLOCK does not preempt synchronous kernel handlers/request_module.
	// The context bounds userspace receive/poll, not a stuck kernel syscall.
	if err := unix.Sendto(s.fd, request, unix.MSG_DONTWAIT, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	buffer := make([]byte, backendNFTMaxDatagram)
	for !d.done {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		wait := min(20, int((remaining+time.Millisecond-1)/time.Millisecond))
		poll := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, wait)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		if poll[0].Revents != unix.POLLIN {
			return nil, errBackendInventory
		}
		n, _, flags, sender, err := unix.Recvmsg(s.fd, buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return nil, err
		}
		peer, ok := sender.(*unix.SockaddrNetlink)
		if !ok || peer.Family != unix.AF_NETLINK || n < 0 || n > len(buffer) || flags&^(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			return nil, errBackendInventory
		}
		if err := d.consume(backendNFTDatagram{Data: buffer[:n], SenderPID: peer.Pid, Groups: peer.Groups, Truncated: flags&unix.MSG_TRUNC != 0, ControlTruncated: flags&unix.MSG_CTRUNC != 0}); err != nil {
			return nil, err
		}
	}
	if err := errors.Join(ctx.Err(), d.finish()); err != nil {
		return nil, err
	}
	return d, nil
}
