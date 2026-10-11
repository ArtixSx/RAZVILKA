//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"syscall"
)

func nfqws2InactiveSystemPlatform() (nfqws2InactivePlatform, error) {
	return nfqws2InactivePlatform{
		procRoot: "/proc", selfPID: os.Getpid(), readlink: os.Readlink,
		protected: func(info os.FileInfo, directory, private bool) bool {
			if info == nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || !directory && !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
				return false
			}
			if private && info.Mode().Perm()&0077 != 0 {
				return false
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			return ok && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid()))
		},
		queues: func(ctx context.Context) ([]nfqwsScopedQueue, error) {
			raw, err := backendInventoryThreadProc(ctx, backendThreadQueues)
			if err != nil {
				return nil, errors.Join(ErrNFQWSScopedQueueInventory, err)
			}
			return nfqwsScopedQueues(string(raw))
		},
		sockets: func(ctx context.Context) (string, error) {
			raw, err := backendInventoryThreadProc(ctx, backendThreadNetlink)
			return string(raw), err
		},
	}, nil
}
