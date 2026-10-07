//go:build linux

package dataplane

import (
	"fmt"
	"os"
	"syscall"
)

func scopedDNSInactivePlatformProof() (scopedDNSInactiveProof, error) {
	return scopedDNSInactiveProof{procRoot: "/proc", selfPID: os.Getpid(), readlink: os.Readlink, threadNetRoot: func() string {
		// Resolve the TID only inside Provider.WithCurrent, after LockOSThread.
		// The explicit task path is also observed on the reviewed stock kernel;
		// absence of an optional thread-self/ns/net link proves nothing here.
		return fmt.Sprintf("/proc/%d/task/%d/net", os.Getpid(), syscall.Gettid())
	}, sameExecutable: func(first, second string) (bool, error) {
		a, err := os.Stat(first)
		if err != nil {
			return false, err
		}
		b, err := os.Stat(second)
		if err != nil {
			return false, err
		}
		return os.SameFile(a, b), nil
	}}, nil
}

func scopedDNSInactiveProtected(info os.FileInfo, directory bool) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || !directory && !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
