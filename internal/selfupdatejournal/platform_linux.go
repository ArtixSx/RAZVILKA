//go:build linux

package selfupdatejournal

import (
	"os"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func lockFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
func fileFlags() int                       { return syscall.O_NOFOLLOW | syscall.O_NONBLOCK }
func syncJournal(root *ownedfs.Root) error { return root.Sync() }
