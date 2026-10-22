//go:build linux

package components

import (
	"os"
	"syscall"
)

func nfqwsInitialMetadata(info os.FileInfo, fixture bool) error {
	if err := trustedManagedNFQWSOwner(info, fixture); err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (!fixture && (stat.Uid != 0 || stat.Gid != 0)) {
		return ErrNFQWSInitialInstall
	}
	return nil
}
