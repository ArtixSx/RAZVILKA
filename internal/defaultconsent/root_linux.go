//go:build linux

package defaultconsent

import (
	"os"
	"syscall"
)

func rootProtected(info os.FileInfo, private bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return false
	}
	if private {
		return info.Mode().Perm()&0077 == 0
	}
	return info.Mode().Perm()&0022 == 0
}
