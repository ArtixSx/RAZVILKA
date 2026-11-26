//go:build linux

package cloudflareprovider

import (
	"os"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func openSnapshotFile(root *ownedfs.Root) (*os.File, error) {
	return root.OpenFile(storeFile, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
