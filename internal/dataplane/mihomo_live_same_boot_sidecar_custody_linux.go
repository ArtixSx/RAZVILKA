//go:build linux

package dataplane

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

// Read-only wait on the descriptor this original cursor already acquired and
// validated before its signal. Never looks up a PID or sends another signal.
func waitMihomoSameBootSidecarExit(ctx context.Context, s *mihomoSameBootSidecar, original *mihomoSameBootStatic) error {
	if ctx == nil || original == nil || s == nil || s.self != s || s.original != original || s.file == nil || s.closed || s.closeErr != nil || !s.validated || !s.attempted {
		if s != nil {
			return errors.Join(ErrMihomoLiveRetirement, s.closeErr)
		}
		return ErrMihomoLiveRetirement
	}
	if _, err := s.file.Stat(); err != nil {
		return errors.Join(ErrMihomoLiveRetirement, err)
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrMihomoLiveRetirement
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		poll := []unix.PollFd{{Fd: int32(s.file.Fd()), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, 20)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n > 0 {
			if poll[0].Revents&unix.POLLIN == 0 || poll[0].Revents & ^int16(unix.POLLIN|unix.POLLHUP) != 0 {
				return ErrMihomoLiveRetirement
			}
			return ctx.Err()
		}
	}
}
