//go:build linux

package cloudflareprovider

import (
	"os"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Nonblocking open closes the stat/open FIFO race. Final symlinks are refused
// by the kernel as well as the anchored path checks; regular files are required.
func openLegacyFile(root *ownedfs.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
