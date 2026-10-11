//go:build linux

package dataplane

import (
	"os"
	"syscall"
)

// Opening a replaced FIFO must not extend a finite read session. The caller
// separately compares the retained inode/type against its prior actual Lstat.
func openWGInactivityObservationFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
