//go:build windows

package dataplane

import (
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"golang.org/x/sys/windows"
)

func openCloudflareScanLockFile(root *ownedfs.Root, create bool) (*os.File, error) {
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	return root.OpenFile(cloudflareScanLockFile, flags, 0o600)
}

func lockCloudflareScanFile(file *os.File) error {
	return windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}

func unlockCloudflareScanFile(file *os.File) {
	_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{})
}
