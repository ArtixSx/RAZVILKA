//go:build linux

package dataplane

import (
	"os"
	"syscall"
)

func retainedSingOpenFlags(write bool) int {
	flags := os.O_RDONLY | syscall.O_NONBLOCK | syscall.O_NOFOLLOW
	if write {
		flags = os.O_RDWR | syscall.O_NONBLOCK | syscall.O_NOFOLLOW
	}
	return flags
}
