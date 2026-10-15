//go:build !windows

package security

import "github.com/ArtixSx/razvilka/internal/ownedfs"

func syncPrivateDirectory(root *ownedfs.Root) error { return root.Sync() }
