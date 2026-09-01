//go:build !linux && !windows

package dataplane

import (
	"errors"
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func openCloudflareScanLockFile(_ *ownedfs.Root, _ bool) (*os.File, error) {
	return nil, errors.New("Cloudflare scan locking is unsupported")
}
func lockCloudflareScanFile(_ *os.File) error {
	return errors.New("Cloudflare scan locking is unsupported")
}
func unlockCloudflareScanFile(_ *os.File) {}
