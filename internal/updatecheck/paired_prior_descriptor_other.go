//go:build !linux

package updatecheck

import (
	"os"
	"runtime"
)

// Only isolated Windows storage tests exercise these functions. The public
// capture API rejects non-Linux, and a Windows artifact cannot validate on
// Linux. This is not a substitute for Unix ownership or native acceptance.
func openPriorArchiveReadOnly(root *os.Root, name string) (*os.File, error) {
	if runtime.GOOS != "windows" {
		return nil, ErrPairedPriorArchive
	}
	return root.OpenFile(name, os.O_RDONLY, 0)
}

func checkPriorArchiveOwner(info os.FileInfo) error {
	if runtime.GOOS != "windows" || info == nil {
		return ErrPairedPriorArchive
	}
	return nil
}
