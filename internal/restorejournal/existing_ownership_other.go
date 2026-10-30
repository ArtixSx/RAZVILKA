//go:build !linux

package restorejournal

import "os"

// No strict offline owner authority is inferred on unsupported platforms.
func existingOwner(os.FileInfo, bool) bool { return false }
