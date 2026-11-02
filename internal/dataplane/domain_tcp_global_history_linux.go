//go:build linux

package dataplane

import (
	"fmt"
	"os"
	"syscall"
)

func domainTCPGlobalOriginalInfo(info os.FileInfo) bool {
	if info == nil || info.Mode() != 0600 || info.Size() < 1 || info.Size() > 16<<20 {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && s.Nlink == 1
}

func domainTCPGlobalRootSame(a, b os.FileInfo) bool {
	if a == nil || b == nil || !networkPolicyPrivateDirectory(a) || !networkPolicyPrivateDirectory(b) || !os.SameFile(a, b) || a.Mode() != b.Mode() {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Uid == uint32(os.Geteuid()) && y.Uid == x.Uid && y.Gid == x.Gid
}

func domainTCPGlobalInfoKey(info os.FileInfo) string {
	if info == nil {
		return ""
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode() != 0600 || s.Uid != uint32(os.Geteuid()) || s.Nlink > 1 {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d:%d:%d:%d:%d:%d:%d:%d", uint64(s.Dev), s.Ino, s.Uid, s.Gid, s.Nlink, info.Mode(), info.Size(), info.ModTime().UnixNano(), s.Ctim.Sec, s.Ctim.Nsec)
}
func domainTCPGlobalInfoSame(a, b os.FileInfo) bool {
	left, right := domainTCPGlobalInfoKey(a), domainTCPGlobalInfoKey(b)
	return left != "" && left == right && os.SameFile(a, b)
}
func domainTCPGlobalRenamedInfo(before, after os.FileInfo) bool {
	if !domainTCPGlobalOriginalInfo(before) || domainTCPGlobalInfoKey(after) == "" || !os.SameFile(before, after) {
		return false
	}
	b, a := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
	return a.Nlink == 0 && b.Uid == a.Uid && b.Gid == a.Gid && before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}
