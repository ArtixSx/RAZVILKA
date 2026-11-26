//go:build linux && (amd64 || arm64)

package netidentity

import (
	"errors"

	"golang.org/x/sys/unix"
)

// Both Linux v6.1 fs/stat.c:222 and fs/proc/fd.c:57-59 expose the same legacy
// real_mount(file->f_path.mnt)->mnt_id. This fresh descriptor query replaces
// only the fdinfo leaf read; stable, mountsMatch, mount-layout, named-path and
// thread/process/namespace bookends remain independent and unchanged.
func (a *audit) mountID(fd int) (uint64, bool) {
	if a == nil || a.ctx == nil || a.ctx.Err() != nil || fd < 0 {
		return 0, false
	}
	var stat unix.Statx_t
	err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stat)
	return a.mountIDAfterStatx(fd, stat, err)
}

// No capability/result cache: fallback still reads the original protected
// procfs descriptor each time. This helper permits adversarial tests of older
// kernels without a mutable syscall hook in the live observer.
func (a *audit) mountIDAfterStatx(fd int, stat unix.Statx_t, callErr error) (uint64, bool) {
	if a == nil || a.ctx == nil || a.ctx.Err() != nil || fd < 0 {
		return 0, false
	}
	if callErr != nil {
		switch {
		case errors.Is(callErr, unix.ENOSYS), errors.Is(callErr, unix.EOPNOTSUPP), errors.Is(callErr, unix.EINVAL), errors.Is(callErr, unix.EPERM), errors.Is(callErr, unix.EACCES):
			return a.mountIDFromFDInfo(fd)
		default:
			return 0, false
		}
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 {
		return a.mountIDFromFDInfo(fd)
	}
	if stat.Mnt_id == 0 || a.ctx.Err() != nil {
		return 0, false
	}
	return stat.Mnt_id, true
}
