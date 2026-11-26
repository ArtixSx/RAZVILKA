//go:build linux

package physicalscope

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

func platformDomainIPv4PolicyDump(ctx context.Context, kind uint16, family byte) ([]message, error) {
	if kind == 34 && family == 2 || kind == 26 && family == 2 || kind == 18 && family == 0 {
		return dump(ctx, kind, family)
	}
	return nil, ErrUnknown
}

func platformDomainIPv4PolicyRoute(ctx context.Context, query DomainIPv4PolicyLookupQuery) (observation DomainIPv4PolicyLookup, resultErr error) {
	fd, port, err := routeSocket(0)
	if err != nil {
		return observation, err
	}
	defer func() {
		if closeErr := unix.Close(fd); closeErr != nil {
			observation = DomainIPv4PolicyLookup{}
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	seq := requestSequence.Add(1)
	if seq == 0 {
		seq = requestSequence.Add(1)
	}
	if err := unix.Sendto(fd, domainIPv4PolicyRouteRequest(query, seq, port), unix.MSG_DONTWAIT, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return observation, err
	}
	var buffer [4096]byte
	for {
		if err := ctx.Err(); err != nil {
			return observation, err
		}
		n, _, flags, from, err := unix.Recvmsg(fd, buffer[:], nil, unix.MSG_DONTWAIT)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if _, err := unix.Poll(poll, 20); err != nil && !errors.Is(err, unix.EINTR) {
				return observation, err
			}
			if poll[0].Revents & ^int16(unix.POLLIN) != 0 {
				return observation, ErrUnknown
			}
			continue
		case err != nil:
			return observation, err
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 || sender.Groups != 0 || flags != 0 || n <= 0 {
			return observation, ErrUnknown
		}
		result, err := decodeDomainIPv4PolicyRouteReply(buffer[:n], query, seq, port, uint32(unix.Geteuid()))
		if err != nil {
			return observation, err
		}
		if _, _, _, _, err := unix.Recvmsg(fd, buffer[:], nil, unix.MSG_DONTWAIT); !errors.Is(err, unix.EAGAIN) {
			return observation, ErrUnknown
		}
		if err := ctx.Err(); err != nil {
			return observation, err
		}
		return result, nil
	}
}
