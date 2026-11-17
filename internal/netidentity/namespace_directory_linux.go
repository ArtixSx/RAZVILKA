//go:build linux

package netidentity

import (
	"context"
	"syscall"
)

// Only the original fixed proc directory reads use this path. A direct syscall
// keeps the private 4KiB buffer on the stack; no callback may retain it.
func readNamespaceDirectoryFD(ctx context.Context, fd int) ([]string, bool, bool, bool) {
	state := newNamespaceDirectoryState()
	buf := make([]byte, 4096)
	total := 0
	for calls := 0; calls < maxDirectoryCalls; calls++ {
		if ctx.Err() != nil || total >= maxDirectoryBytes {
			return state.names, state.unknown, false, false
		}
		chunk := buf
		if remaining := maxDirectoryBytes - total; remaining < len(chunk) {
			chunk = chunk[:remaining]
		}
		n, err := syscall.ReadDirent(fd, chunk)
		if err != nil || n < 0 || n > len(chunk) {
			return state.names, state.unknown, false, false
		}
		if n == 0 {
			return state.names, state.unknown, true, state.dot && state.dotdot
		}
		total += n
		if !state.consume(chunk, n) {
			return state.names, state.unknown, false, false
		}
	}
	return state.names, state.unknown, false, false
}
