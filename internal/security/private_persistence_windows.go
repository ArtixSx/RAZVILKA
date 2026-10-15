//go:build windows

package security

import "github.com/ArtixSx/razvilka/internal/ownedfs"

// Windows is the process-crash development/test backend, matching the other
// project journals. File Sync and atomic replacement do not establish a
// directory-entry power-loss guarantee on this backend.
func syncPrivateDirectory(_ *ownedfs.Root) error { return nil }
