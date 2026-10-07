//go:build !linux

package defaultconsent

import "os"

// Portable ownership models are not Linux deployment authority.
func rootProtected(info os.FileInfo, private bool) bool { return info.IsDir() }
