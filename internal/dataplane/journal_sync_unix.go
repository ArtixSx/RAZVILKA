//go:build !windows

package dataplane

import "github.com/ArtixSx/razvilka/internal/ownedfs"

func syncDataplaneJournalDirectory(root *ownedfs.Root) error { return root.Sync() }
