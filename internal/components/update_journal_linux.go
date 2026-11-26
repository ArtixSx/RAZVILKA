//go:build linux

package components

import (
	"os"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func lockUpdateFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
func updateFileFlags() int                         { return syscall.O_NOFOLLOW | syscall.O_NONBLOCK }
func syncUpdateDirectory(root *ownedfs.Root) error { return root.Sync() }
