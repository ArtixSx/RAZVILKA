//go:build windows

package dataplane

import "github.com/ArtixSx/razvilka/internal/ownedfs"

// Windows is the process-crash development backend. File Sync and rename here
// do not establish router/filesystem power-loss durability.
func syncDataplaneJournalDirectory(_ *ownedfs.Root) error { return nil }
