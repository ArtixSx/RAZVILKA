//go:build linux

package dataplane

import (
	"os"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func openCloudflareScanLockFile(root *ownedfs.Root, create bool) (*os.File, error) {
	flags := os.O_RDWR | syscall.O_NONBLOCK | syscall.O_NOFOLLOW
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	return root.OpenFile(cloudflareScanLockFile, flags, 0o600)
}

func lockCloudflareScanFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func unlockCloudflareScanFile(file *os.File) { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN) }
