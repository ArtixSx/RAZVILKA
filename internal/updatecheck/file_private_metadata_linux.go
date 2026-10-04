//go:build linux

package updatecheck

import (
	"os"
	"syscall"
)

func openPrivateReadOnly(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func checkPrivateDescriptorOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	// Production load requires euid0 and root-owned ancestors. Isolated
	// native fixtures use their own euid under the private ownership override.
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrFileProtocol
	}
	return nil
}
