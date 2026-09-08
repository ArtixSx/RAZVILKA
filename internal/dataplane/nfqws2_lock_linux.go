//go:build linux

package dataplane

import (
	"os"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func openNFQWS2LockFile(root *ownedfs.Root, name string, create bool) (*os.File, error) {
	flags := os.O_RDWR | syscall.O_NONBLOCK | syscall.O_NOFOLLOW
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	return root.OpenFile(name, flags, 0o600)
}
