//go:build linux

package app

import (
	"errors"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"os"
	"syscall"
)

func nfqws2HookPrivateOwner(info os.FileInfo) error {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return errors.New("unsafe NFQWS2 hook recovery ownership or permissions")
	}
	return nil
}

func nfqws2HookInstallationOwner(info os.FileInfo) error {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe Entware installation owner or permissions")
	}
	return nil
}

func openNFQWS2HookFile(r *ownedfs.Root) (*os.File, error) {
	return r.OpenFile(nfqws2HookJournalName, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
