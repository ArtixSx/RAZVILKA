//go:build !linux

package dataplane

import "os"

func scopedDNSInactivePlatformProof() (scopedDNSInactiveProof, error) {
	return scopedDNSInactiveProof{}, ErrScopedDNSRuntimeInactive
}

// Private fixture protocol only; exported observation refuses this platform.
func scopedDNSInactiveProtected(info os.FileInfo, directory bool) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 && info.IsDir() == directory && (directory || info.Mode().IsRegular())
}
