//go:build linux

package updatecheck

import (
	"os"
	"syscall"
)

func offlinePersistentIdentity(info os.FileInfo) (offlineRetryIdentity, error) {
	if !safePriorSourceInfo(info) {
		return offlineRetryIdentity{}, ErrPairedOfflineRestore
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return offlineRetryIdentity{}, ErrPairedOfflineRestore
	}
	return offlineRetryIdentity{uint64(stat.Dev), stat.Ino, uint32(info.Mode()), info.Size(), info.ModTime().UnixNano()}, nil
}
