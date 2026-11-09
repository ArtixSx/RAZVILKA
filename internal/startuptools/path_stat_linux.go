//go:build linux && (amd64 || arm64)

package startuptools

import (
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// Only syscall argument/output scratch is pooled. Neither the named path nor
// any metadata result survives a call; every observation still enters fstatat.
type freshPathScratch struct {
	path [4096]byte
	stat syscall.Stat_t
}

var freshPathScratchPool = sync.Pool{New: func() any { return new(freshPathScratch) }}

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
	if len(path) >= 4096 || strings.IndexByte(path, 0) >= 0 {
		// Preserve the original invalid/overlong argument behavior, including
		// BytePtrFromString's EINVAL before the syscall for embedded NUL.
		var after syscall.Stat_t
		if err := syscall.Lstat(path, &after); err != nil {
			return false, err
		}
		return sameReviewedStat(before, &after), nil
	}
	scratch := freshPathScratchPool.Get().(*freshPathScratch)
	scratch.stat = syscall.Stat_t{}
	copy(scratch.path[:], path)
	scratch.path[len(path)] = 0
	// Match syscall.Lstat on these architectures: AT_FDCWD (-100), no-follow,
	// and exactly one Syscall6 (including its unchanged EINTR behavior). Keep
	// pointer conversions in the syscall expression, as in Go's generated
	// wrapper, and retain exclusive scratch until the synchronous call ends.
	const atFDCWD = ^uintptr(99)
	const atSymlinkNoFollow = 0x100
	_, _, errno := syscall.Syscall6(freshPathStatSyscall, atFDCWD,
		uintptr(unsafe.Pointer(&scratch.path[0])), uintptr(unsafe.Pointer(&scratch.stat)),
		atSymlinkNoFollow, 0, 0)
	same := errno == 0 && sameReviewedStat(before, &scratch.stat)
	clear(scratch.path[:len(path)+1])
	scratch.stat = syscall.Stat_t{}
	freshPathScratchPool.Put(scratch)
	if errno != 0 {
		return false, errno
	}
	return same, nil
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
