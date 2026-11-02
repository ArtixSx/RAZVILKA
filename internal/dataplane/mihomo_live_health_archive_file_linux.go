//go:build linux

package dataplane

import (
	"os"
	"syscall"
)

// Exact comparison helpers copied from main's cold-file reader. This isolated
// fixture branch does not import the unrelated cold coordinator; main already
// defines these same helpers in mihomo_live_cold_file_linux.go.
func mihomoColdFileValid(info os.FileInfo) bool {
	return info != nil && executionHistoryOwner(info, false) && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && info.Mode().Perm()&0077 == 0 && info.Size() >= 0 && info.Size() <= bootRetirementLimit
}

func mihomoColdFileSame(a, b os.FileInfo) bool {
	if !mihomoColdFileValid(a) || !mihomoColdFileValid(b) || !os.SameFile(a, b) || a.Size() != b.Size() || a.Mode() != b.Mode() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Ctim == y.Ctim && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink
}
