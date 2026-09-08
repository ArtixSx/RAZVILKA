//go:build windows

package restorejournal

import (
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"golang.org/x/sys/windows"
)

func openPrivate(root *ownedfs.Root, name string, create bool) (*os.File, error) {
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	return root.OpenFile(name, flags, 0o600)
}

func lockFile(file *os.File) error {
	return windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}

// Windows is a process-crash development/test backend only. File Sync and
// atomic replacement do not establish directory-entry power-loss durability.
func syncJournalDir(_ *ownedfs.Root) error { return nil }

func openReadOnly(root *ownedfs.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY, 0)
}
