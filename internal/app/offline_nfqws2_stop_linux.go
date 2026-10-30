//go:build linux

package app

import (
	"fmt"
	"os"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func offlineNFQDirectoryIdentity(info os.FileInfo, private bool) (string, error) {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || s.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 || private && info.Mode().Perm()&0077 != 0 {
		return "", ErrOfflineNFQWS2Stop
	}
	return fmt.Sprintf("%d:%d", uint64(s.Dev), uint64(s.Ino)), nil
}

func offlineNFQOpenFile(root *ownedfs.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
