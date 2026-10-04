//go:build linux

package dataplane

import (
	"net"
	"os"
	"syscall"
)

func proxyInactivePlatformProof() (proxyInactiveProof, error) {
	return proxyInactiveProof{procRoot: "/proc", selfPID: os.Getpid(), interfaces: net.Interfaces, readlink: os.Readlink}, nil
}

func proxyInactivePrivateDirectory(info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
