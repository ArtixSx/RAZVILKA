//go:build !linux

package cloudflareprovider

import (
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Development fallback; Linux nonblocking/non-follow open is tested separately.
func openLegacyFile(root *ownedfs.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY, 0)
}
