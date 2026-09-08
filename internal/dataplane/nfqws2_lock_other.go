//go:build !linux && !windows

package dataplane

import (
	"errors"
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func openNFQWS2LockFile(*ownedfs.Root, string, bool) (*os.File, error) {
	return nil, errors.New("NFQWS2 shared resource locking is unavailable")
}
