//go:build linux

package dataplane

import (
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const usqueLiveSessionReadFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK

func usqueInitialPrivateSession(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1 && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0
}

func usqueInitialProtectedPath(path string) bool {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		sticky := info.IsDir() && info.Mode()&os.ModeSticky != 0
		if !ok || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) || !sticky && info.Mode().Perm()&0o022 != 0 {
			return false
		}
		if filepath.Dir(current) == current {
			return true
		}
	}
}

func usqueInitialSameOwner(before, current os.FileInfo) bool {
	x, beforeOK := before.Sys().(*syscall.Stat_t)
	y, currentOK := current.Sys().(*syscall.Stat_t)
	return beforeOK && currentOK && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Ctim == y.Ctim
}
