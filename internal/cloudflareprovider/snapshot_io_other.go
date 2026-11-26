//go:build !linux

package cloudflareprovider

import (
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func openSnapshotFile(root *ownedfs.Root) (*os.File, error) {
	return root.OpenFile(storeFile, os.O_RDONLY, 0)
}
