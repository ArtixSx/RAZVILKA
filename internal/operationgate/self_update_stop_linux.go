//go:build linux

package operationgate

import (
	"errors"
	"os"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

var errControlLockBusy = errors.New("control authority lock busy")

func controlPrivate(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0
}
func controlFileFlags() int { return syscall.O_NOFOLLOW | syscall.O_NONBLOCK }
func controlFileLock(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return errControlLockBusy
	}
	return err
}
func controlSync(root *ownedfs.Root) error { return root.Sync() }
