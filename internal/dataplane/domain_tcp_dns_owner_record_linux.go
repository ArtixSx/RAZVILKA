//go:build linux

package dataplane

import (
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

func domainTCPDNSOwnerRenameNoReplace(directory *os.File, from, to string) error {
	return unix.Renameat2(int(directory.Fd()), from, int(directory.Fd()), to, unix.RENAME_NOREPLACE)
}

func domainTCPDNSOwnerPrivateFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && s.Nlink == 1
}
func domainTCPDNSOwnerDirectory(info os.FileInfo) bool { return proxyInactivePrivateDirectory(info) }
