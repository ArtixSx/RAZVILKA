//go:build linux && (amd64 || arm64)

package startuptools

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// Read the SAME named node on every pass without constructing an os.FileInfo.
// No descriptor, path resolution or metadata result is retained here. Lstat
// keeps the original no-follow semantics; both surrounding passes and every
// symlink/negative lookup/membership check remain in pathsCurrent.
func freshPathNode(path string, expected os.FileInfo) (bool, error) {
	if expected == nil {
		return false, nil
	}
	before, ok := expected.Sys().(*syscall.Stat_t)
	if !ok || before == nil {
		return false, nil
	}
	var after syscall.Stat_t
	if len(path) >= 4096 || strings.IndexByte(path, 0) >= 0 {
		if err := syscall.Lstat(path, &after); err != nil {
			return false, err
		}
		return sameReviewedStat(before, &after), nil
	}
	// Go Syscall6 keeps these stack pointers live through its synchronous call.
	// No pathname, FD or metadata survives this observation; every call still
	// performs the original fstatat with the same no-follow/error semantics.
	var argument [4096]byte
	copy(argument[:], path)
	_, _, errno := syscall.Syscall6(freshPathStatSyscall, ^uintptr(99),
		uintptr(unsafe.Pointer(&argument[0])), uintptr(unsafe.Pointer(&after)), 0x100, 0, 0)
	if errno != 0 {
		return false, errno
	}
	return sameReviewedStat(before, &after), nil
}

// Equivalent owner/identity/mode/ctime/size/mtime checks to sameNode for
// reviewed Linux nodes. Directory ctime/size/mtime are deliberately excluded,
// as before: actual extension membership is checked independently.
func sameReviewedStat(before, after *syscall.Stat_t) bool {
	if before == nil || after == nil || after.Uid != 0 ||
		after.Mode&syscall.S_IFMT != syscall.S_IFLNK && after.Mode&0022 != 0 ||
		after.Mode&(syscall.S_ISUID|syscall.S_ISGID) != 0 ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode ||
		before.Uid != after.Uid || before.Gid != after.Gid {
		return false
	}
	return after.Mode&syscall.S_IFMT == syscall.S_IFDIR ||
		before.Ctim == after.Ctim && before.Size == after.Size && before.Mtim == after.Mtim
}
