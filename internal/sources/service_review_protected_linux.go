//go:build linux

package sources

import (
	"os"
	"syscall"
)

func serviceReviewDirectoryOwner(info os.FileInfo, target bool) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 && st.Uid != uint32(os.Geteuid()) {
		return false
	}
	if target {
		return st.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0022 == 0
	}
	return info.Mode().Perm()&0022 == 0 || info.Mode()&os.ModeSticky != 0 && st.Uid == 0
}

func serviceReviewFileOwner(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0022 == 0
}

func serviceReviewSameOwner(before, after os.FileInfo) bool {
	b, bok := before.Sys().(*syscall.Stat_t)
	a, aok := after.Sys().(*syscall.Stat_t)
	return bok && aok && b.Uid == a.Uid && b.Gid == a.Gid && before.Mode() == after.Mode()
}
