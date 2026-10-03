//go:build windows

package selfupdatejournal

import (
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"golang.org/x/sys/windows"
	"os"
)

func lockFile(file *os.File) error {
	return windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}
func fileFlags() int { return 0 }

// Windows validates process interruption only, not power-loss durability.
func syncJournal(_ *ownedfs.Root) error { return nil }
