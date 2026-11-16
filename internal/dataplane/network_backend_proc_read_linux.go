//go:build linux

package dataplane

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
)

// Read only an already anchored, checked proc leaf. The caller retains and
// closes the original descriptor after its unchanged closing observations.
// No polling or descriptor-wrapper state is installed on these finite files.
func backendInventoryReadProcFD(ctx context.Context, fd, limit int) ([]byte, error) {
	return backendInventoryReadProcBounded(ctx, limit, func(p []byte) (int, error) { return unix.Read(fd, p) })
}
func backendInventoryReadProcBounded(ctx context.Context, limit int, read func([]byte) (int, error)) ([]byte, error) {
	if ctx == nil || limit <= 0 || limit > 1<<20 || read == nil {
		return nil, errBackendInventory
	}
	var data []byte
	var block [4096]byte
	for {
		if err := ctx.Err(); err != nil {
			clear(data)
			return nil, err
		}
		want := min(len(block), limit+1-len(data))
		n, err := read(block[:want])
		if errors.Is(err, unix.EINTR) && n <= 0 {
			continue
		}
		if err != nil || n < 0 || n > want || n > limit-len(data) {
			clear(data)
			return nil, errors.Join(errBackendInventory, err)
		}
		if n == 0 {
			if err := ctx.Err(); err != nil {
				clear(data)
				return nil, err
			}
			return data, nil
		}
		data = append(data, block[:n]...)
	}
}
