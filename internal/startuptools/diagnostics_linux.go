//go:build linux && (amd64 || arm64)

package startuptools

import (
	"errors"
	"os"
	"syscall"
)

func pathOwnerFailure(path string, info os.FileInfo, err error) error {
	reason := "STAT"
	if errors.Is(err, os.ErrNotExist) {
		reason = "MISSING"
	} else if err == nil && info != nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			switch {
			case stat.Uid != 0:
				reason = "UID"
			case info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0022 != 0:
				reason = "WRITE_MODE"
			case info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0:
				reason = "SETID"
			}
		}
	}
	return at("PATH_OWNER_"+pathCategory(path)+"_"+reason, err)
}
