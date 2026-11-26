//go:build linux

package dataplane

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"syscall"
)

func originalProcessPIDAbsent(pid int) error {
	if _, err := os.Lstat("/proc/" + strconv.Itoa(pid)); !errors.Is(err, os.ErrNotExist) {
		return ErrOriginalProcessCleanup // Includes PID reuse; never delete its metadata.
	}
	return nil
}

func originalProcessListenerAbsent(ctx context.Context, port int) error {
	for _, table := range []struct {
		path string
		v6   bool
	}{{"/proc/self/net/tcp", false}, {"/proc/self/net/tcp6", true}} {
		if ctx.Err() != nil {
			return ErrOriginalProcessCleanup
		}
		f, err := os.Open(table.path)
		if table.v6 && errors.Is(err, os.ErrNotExist) {
			fd, socketErr := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
			if socketErr == nil {
				_ = syscall.Close(fd)
			}
			if errors.Is(socketErr, syscall.EAFNOSUPPORT) {
				continue
			}
		}
		if err != nil {
			return ErrOriginalProcessCleanup
		}
		raw, readErr := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || ctx.Err() != nil || proxyInactiveSocketTable(raw, table.v6, port) != nil {
			return ErrOriginalProcessCleanup
		}
	}
	return ctx.Err()
}
