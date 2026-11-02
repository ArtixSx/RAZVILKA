//go:build linux

package dataplane

import (
	"golang.org/x/sys/unix"
	"os"
)

func mihomoColdRenameNoReplace(from, to *os.File) error {
	return unix.Renameat2(int(from.Fd()), "mihomo", int(to.Fd()), "runtime", unix.RENAME_NOREPLACE)
}
