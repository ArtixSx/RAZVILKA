//go:build linux

package dataplane

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"strings"
)

func mihomoColdRenameNoReplace(from, to *os.File) error {
	return unix.Renameat2(int(from.Fd()), "mihomo", int(to.Fd()), "runtime", unix.RENAME_NOREPLACE)
}

// Only newly authored documentary markers use no-replace publication.
func mihomoColdPublishNew(root *os.Root, temporary, name string) (published bool, result error) {
	if root == nil || (name != "retirement.json" && name != "completed.json") || !strings.HasPrefix(temporary, ".mihomo-retirement-") || !validMihomoColdHomeHex(strings.TrimPrefix(temporary, ".mihomo-retirement-")) {
		return false, ErrMihomoLiveRetirement
	}
	dir, err := root.Open(".")
	if err != nil {
		return false, err
	}
	defer func() { result = errors.Join(result, dir.Close()) }()
	if err := unix.Renameat2(int(dir.Fd()), temporary, int(dir.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
		return false, err
	}
	return true, nil
}
