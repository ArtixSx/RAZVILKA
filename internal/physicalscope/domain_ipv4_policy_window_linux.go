//go:build linux

package physicalscope

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

// These groups are available via the original nl_groups bit mask, including
// on Linux 4.9. The subscription does not request netfilter or packet data.
const domainIPv4PolicyGroups = unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV4_RULE

type kernelDomainIPv4PolicyWindow struct {
	fd, anchor int
	port       uint32
	socket     unix.Stat_t
}

func platformOpenDomainIPv4PolicyWindow(ctx context.Context) (domainIPv4PolicyWindowMonitor, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, port, err := routeSocket(domainIPv4PolicyGroups)
	if err != nil {
		return nil, err
	}
	var socket unix.Stat_t
	if err := unix.Fstat(fd, &socket); err != nil || socket.Mode&unix.S_IFMT != unix.S_IFSOCK || socket.Ino == 0 {
		return nil, errors.Join(at("domain-policy-window.descriptor", err), unix.Close(fd))
	}
	// Keep the socket inode alive even if the working descriptor is replaced.
	// SO_COOKIE is not available on the original 4.9 Linux socket interface.
	anchor, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, errors.Join(at("domain-policy-window.retain", err), unix.Close(fd))
	}
	window := &kernelDomainIPv4PolicyWindow{fd: fd, anchor: anchor, port: port, socket: socket}
	if err := window.current(); err != nil {
		return nil, errors.Join(err, window.close())
	}
	return window, nil
}

func (w *kernelDomainIPv4PolicyWindow) owns(fd int) error {
	var actual unix.Stat_t
	if err := unix.Fstat(fd, &actual); err != nil || actual.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		actual.Ino != w.socket.Ino || actual.Dev != w.socket.Dev {
		return at("domain-policy-window.descriptor", err)
	}
	name, err := unix.Getsockname(fd)
	bound, ok := name.(*unix.SockaddrNetlink)
	if err != nil || !ok || bound.Family != unix.AF_NETLINK || bound.Pid != w.port || bound.Groups != domainIPv4PolicyGroups {
		return at("domain-policy-window.subscription", err)
	}
	return nil
}

func (w *kernelDomainIPv4PolicyWindow) current() error {
	return errors.Join(w.owns(w.anchor), w.owns(w.fd))
}

func (w *kernelDomainIPv4PolicyWindow) quiet(ctx context.Context) error {
	if err := w.current(); err != nil {
		return err
	}
	// Any datagram revokes the observation. There is no need to decode or
	// skip events, and the existing receiver rejects truncation and foreign
	// senders. Loss (ENOBUFS) is a refusal, never an empty queue.
	var scratch [4096]byte
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := receive(w.fd, scratch[:])
		switch {
		case err == nil:
			return ErrDomainIPv4PolicyWindowChanged
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			return errors.Join(w.current(), ctx.Err())
		default:
			return at("domain-policy-window.notifications", err)
		}
	}
}

func (w *kernelDomainIPv4PolicyWindow) close() error {
	var result error
	for _, fd := range [2]int{w.fd, w.anchor} {
		err := w.owns(fd)
		if err == nil {
			err = unix.Close(fd)
		}
		result = errors.Join(result, err)
	}
	return result
}
