//go:build linux

package dataplane

import (
	"fmt"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"os"
	"syscall"
)

func executionHistoryOpen(root *ownedfs.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
func executionHistoryOwner(info os.FileInfo, directory bool) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || info.IsDir() != directory || !directory && !info.Mode().IsRegular() {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && (directory || s.Nlink == 1)
}
func executionHistoryIdentity(info os.FileInfo) string {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d:%d:%d", s.Dev, s.Ino, s.Uid, s.Gid, s.Nlink)
}
