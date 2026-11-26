//go:build windows

package operationgate

import (
	"errors"
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"golang.org/x/sys/windows"
)

var errControlLockBusy = errors.New("control authority lock busy")

func controlPrivate(os.FileInfo) bool { return true }
func controlFileFlags() int           { return 0 }
func controlFileLock(f *os.File) error {
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return errControlLockBusy
	}
	return err
}

// Windows checks process interruption only, never power-loss durability.
func controlSync(*ownedfs.Root) error { return nil }
