//go:build linux

package components

import (
	"fmt"
	"os"
	"syscall"
)

func mihomoFileIdentity(info os.FileInfo) string {
	if info == nil {
		return ""
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("uid=%d,gid=%d,dev=%d,ino=%d,nlink=%d", stat.Uid, stat.Gid, stat.Dev, stat.Ino, stat.Nlink)
}

func mihomoInstalledOwner(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0755 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

func mihomoArtifactOwner(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0555 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}
