//go:build !linux

package dnscontrol

import "os"

// Source-level fixture policy only; SAME native adapter cannot grant synthetic
// publication on this platform. These models do not prove Windows ACLs.
func syntheticDNSProtectedRoot(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrSyntheticDNSMapping
	}
	return nil
}

func syntheticDNSProtectedFile(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
