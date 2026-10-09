//go:build !linux

package sources

import "os"

// Portable local source models retain real descriptors/incarnations. Linux
// additionally enforces the actual UID and writable-ancestor boundary.
func serviceReviewDirectoryOwner(os.FileInfo, bool) bool    { return true }
func serviceReviewFileOwner(os.FileInfo) bool               { return true }
func serviceReviewSameOwner(before, after os.FileInfo) bool { return before.Mode() == after.Mode() }
