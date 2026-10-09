//go:build linux

package dnscontrol

import (
	"os"
	"path/filepath"
	"syscall"
)

// Same owner/mode policy as the existing protected effect/process roots:
// private current-euid leaf, root/current-euid ancestors, no symlinks or
// writable ancestors. Only the fixed sticky /tmp test boundary is allowed;
// its next private owner directory still prevents foreign unlink/rename.
func syntheticDNSProtectedRoot(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrSyntheticDNSMapping
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrSyntheticDNSMapping
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
			return ErrSyntheticDNSMapping
		}
		if current == path {
			if stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
				return ErrSyntheticDNSMapping
			}
		} else if info.Mode().Perm()&0022 != 0 && !(current == "/tmp" && info.Mode()&os.ModeSticky != 0) {
			return ErrSyntheticDNSMapping
		}
		if next := filepath.Dir(current); next == current {
			return nil
		}
	}
}

func syntheticDNSProtectedFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
