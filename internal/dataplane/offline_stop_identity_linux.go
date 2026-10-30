//go:build linux

package dataplane

import (
	"fmt"
	"os"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func offlineStopDirectoryIdentity(info os.FileInfo) (string, error) {
	if info == nil {
		return "", ErrReviewChanged
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || s.Uid != uint32(os.Geteuid()) {
		return "", ErrReviewChanged
	}
	return fmt.Sprintf("%d:%d", uint64(s.Dev), uint64(s.Ino)), nil
}

func offlineStopPrivateFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid())
}

func offlineStopOpenFile(root *ownedfs.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func offlineStopNativeFileIdentity(info os.FileInfo) (string, error) {
	if info == nil {
		return "", ErrReviewChanged
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrReviewChanged
	}
	return fmt.Sprintf("%d:%d:%d:%d:%d:%d:%d", uint64(s.Dev), uint64(s.Ino), s.Uid, s.Gid, uint32(info.Mode()), info.Size(), info.ModTime().UnixNano()), nil
}
