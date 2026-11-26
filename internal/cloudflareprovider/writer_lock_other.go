//go:build !linux && !windows

package cloudflareprovider

import (
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Unsupported platforms must not silently fall back to guessing stale PIDs.
// Read-only previews remain available; a tested OS lock adapter is required.
func openWriterFile(_ *ownedfs.Root, _ bool) (*os.File, error) { return nil, ErrBusy }
func lockWriterFile(_ *os.File) error                          { return ErrBusy }
func unlockWriterFile(_ *os.File)                              {}
