//go:build linux

package dataplane

import (
	"context"
	"encoding/binary"
	"errors"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Called inside the original same-thread network identity bracket. GETQDISC
// observes ALL interfaces: ip-link's root qdisc field alone misses clsact and
// ingress classifiers. Only known classless roots are supported here.
func domainTCPBaselineQdiscs(ctx context.Context) (result error) {
	if xraySelectedTCPFinite(ctx) != nil {
		return ErrDomainTCPBaselineKernel
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unix.Close(fd)) }()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return err
	}
	local, ok := address.(*unix.SockaddrNetlink)
	if !ok || local.Pid == 0 || local.Groups != 0 {
		return ErrDomainTCPBaselineKernel
	}
	request := make([]byte, unix.NLMSG_HDRLEN+20)
	binary.NativeEndian.PutUint32(request, uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], unix.RTM_GETQDISC)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:], 1)
	binary.NativeEndian.PutUint32(request[12:], local.Pid)
	if err := unix.Sendto(fd, request, unix.MSG_DONTWAIT, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buffer := make([]byte, 65536)
	seen := map[int32]bool{}
	total := 0
	deadline, _ := ctx.Deadline()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		left := time.Until(deadline)
		if left <= 0 {
			return context.DeadlineExceeded
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, min(20, int((left+time.Millisecond-1)/time.Millisecond)))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		if poll[0].Revents != unix.POLLIN {
			return ErrDomainTCPBaselineKernel
		}
		n, _, flags, sender, err := unix.Recvmsg(fd, buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return err
		}
		peer, ok := sender.(*unix.SockaddrNetlink)
		if !ok || peer.Pid != 0 || peer.Groups != 0 || flags != 0 || n == 0 {
			return ErrDomainTCPBaselineKernel
		}
		total += n
		if total > 1<<20 {
			return ErrDomainTCPBaselineKernel
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return err
		}
		for index, message := range messages {
			if message.Header.Seq != 1 || message.Header.Pid != local.Pid || message.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return ErrDomainTCPBaselineKernel
			}
			if message.Header.Type == unix.NLMSG_DONE {
				if index != len(messages)-1 || len(message.Data) != 4 || binary.NativeEndian.Uint32(message.Data) != 0 || len(seen) == 0 {
					return ErrDomainTCPBaselineKernel
				}
				return ctx.Err()
			}
			if message.Header.Type != unix.RTM_NEWQDISC || message.Header.Flags&unix.NLM_F_MULTI == 0 {
				return ErrDomainTCPBaselineKernel
			}
			if err := domainTCPBaselineQdisc(message.Data, seen); err != nil {
				return err
			}
		}
	}
}

func domainTCPBaselineQdisc(data []byte, seen map[int32]bool) error {
	if len(data) < 20 || data[0] != unix.AF_UNSPEC || data[1] != 0 || binary.NativeEndian.Uint16(data[2:]) != 0 {
		return ErrDomainTCPBaselineKernel
	}
	index := int32(binary.NativeEndian.Uint32(data[4:]))
	if index <= 0 || seen[index] || len(seen) >= 256 || binary.NativeEndian.Uint32(data[12:]) != 0xffffffff {
		return ErrDomainTCPBaselineKernel
	}
	kind := ""
	for attributes := data[20:]; len(attributes) > 0; {
		if len(attributes) < 4 {
			return ErrDomainTCPBaselineKernel
		}
		length := int(binary.NativeEndian.Uint16(attributes))
		aligned := (length + 3) &^ 3
		if length < 4 || aligned > len(attributes) {
			return ErrDomainTCPBaselineKernel
		}
		if binary.NativeEndian.Uint16(attributes[2:]) == 1 {
			if kind != "" {
				return ErrDomainTCPBaselineKernel
			}
			value := attributes[4:length]
			if len(value) == 0 || value[len(value)-1] != 0 {
				return ErrDomainTCPBaselineKernel
			}
			kind = string(value[:len(value)-1])
		}
		attributes = attributes[aligned:]
	}
	if kind != "noqueue" && kind != "fq_codel" && kind != "pfifo_fast" {
		return ErrDomainTCPBaselineKernel
	}
	seen[index] = true
	return nil
}
