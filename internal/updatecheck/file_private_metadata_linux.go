//go:build linux

package updatecheck

import (
	"os"
	"syscall"
)

func checkPrivateDescriptorOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	// Production load requires euid0 and root-owned ancestors. Isolated
	// native fixtures use their own euid under the private ownership override.
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrFileProtocol
	}
	return nil
}
