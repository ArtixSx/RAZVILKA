//go:build windows

package dataplane

import (
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func openNFQWS2LockFile(root *ownedfs.Root, name string, create bool) (*os.File, error) {
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	return root.OpenFile(name, flags, 0o600)
}
