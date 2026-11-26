//go:build linux

package restorejournal

import (
	"os"
	"syscall"
)

// Strict offline admission requires the current operator's actual owner, not
// merely private-looking mode bits. Regular files must have no hardlink alias.
func existingOwner(info os.FileInfo, private bool) bool {
	if info == nil || !info.IsDir() && !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || private && info.Mode().Perm()&0o077 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && (!info.Mode().IsRegular() || stat.Nlink == 1)
}
