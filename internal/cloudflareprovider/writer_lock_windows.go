//go:build windows

package cloudflareprovider

import (
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"golang.org/x/sys/windows"
)

func openWriterFile(root *ownedfs.Root, create bool) (*os.File, error) {
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	return root.OpenFile(writerLockFile, flags, 0o600)
}

func lockWriterFile(file *os.File) error {
	return windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}

func unlockWriterFile(file *os.File) {
	_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{})
}
