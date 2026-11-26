//go:build linux

package components

import (
	"fmt"
	"os"
	"syscall"
)

const hevRetainedReadFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK

func hevRetainedOwner(info os.FileInfo, directory bool) (string, bool) {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || directory != info.IsDir() || !directory && !info.Mode().IsRegular() {
		return "", false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || !directory && owner.Nlink != 1 {
		return "", false
	}
	return fmt.Sprintf("uid=%d,gid=%d,dev=%d,ino=%d,nlink=%d", owner.Uid, owner.Gid, owner.Dev, owner.Ino, owner.Nlink), true
}
