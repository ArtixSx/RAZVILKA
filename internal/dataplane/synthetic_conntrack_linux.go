//go:build linux

package dataplane

import (
	"context"
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

// Called only inside the ORIGINAL provider's same-thread bracket. Reuse the
// existing unicast NETLINK_NETFILTER transport, not its NFT request/decoder.
// The sole request here is CT_GET(AF_INET,DUMP). A kernel may autoload its
// module; NONBLOCK cannot preempt that synchronous kernel handler.
func readSyntheticConntrack(ctx context.Context) (result syntheticCTImage, resultErr error) {
	if ctx == nil || ctx.Err() != nil {
		return result, errSyntheticConntrack
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > 2*time.Second {
		return result, errSyntheticConntrack
	}
	session, err := openBackendNFTSocket(ctx)
	if err != nil {
		return result, errors.Join(errSyntheticConntrack, err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			result = syntheticCTImage{}
			resultErr = errors.Join(errSyntheticConntrack, resultErr, err)
		}
	}()
	s, ok := session.(*backendNFTSocket)
	if !ok {
		return result, errSyntheticConntrack
	}
	request, err := syntheticCTRequest(s.sequence, s.port)
	if err != nil {
		return result, err
	}
	d, err := newSyntheticCTDecoder(s.sequence, s.port)
	if err != nil {
		return result, err
	}
	buffer := make([]byte, 65536)
	if _, queued, err := s.receive(buffer); err != nil || queued {
		return result, errors.Join(errSyntheticConntrack, err)
	}
	if err := unix.Sendto(s.fd, request, unix.MSG_DONTWAIT, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return result, errors.Join(errSyntheticConntrack, err)
	}
	for !d.done {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return result, context.DeadlineExceeded
		}
		poll := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, min(20, int((remaining+time.Millisecond-1)/time.Millisecond)))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return result, errors.Join(errSyntheticConntrack, err)
		}
		if n == 0 {
			continue
		}
		if poll[0].Revents != unix.POLLIN {
			return result, errSyntheticConntrack
		}
		packet, received, err := s.receive(buffer)
		if err != nil {
			return result, errors.Join(errSyntheticConntrack, err)
		}
		if received {
			if err := d.consume(packet); err != nil {
				return result, err
			}
		}
	}
	result, err = d.finishReceive(func() (backendNFTDatagram, bool, error) { return s.receive(buffer) })
	if err != nil || ctx.Err() != nil {
		return syntheticCTImage{}, errors.Join(errSyntheticConntrack, err, ctx.Err())
	}
	return result, nil
}
