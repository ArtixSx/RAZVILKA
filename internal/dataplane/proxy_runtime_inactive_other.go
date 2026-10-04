//go:build !linux

package dataplane

import "os"

func proxyInactivePlatformProof() (proxyInactiveProof, error) {
	return proxyInactiveProof{}, ErrProxyRuntimeInactive
}

// Portable local fixtures exercise the same bounded read-only protocol; the
// exported observer never grants inactivity on an unsupported platform.
func proxyInactivePrivateDirectory(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}
