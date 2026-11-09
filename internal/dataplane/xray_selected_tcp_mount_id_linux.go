//go:build linux

package dataplane

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

// Linux v6.1 fs/stat.c:222 and fs/proc/fd.c:57-59 expose the SAME
// real_mount(file->f_path.mnt)->mnt_id. AT_EMPTY_PATH addresses this held FD,
// not its pathname; STATX_MNT_ID_UNIQUE is deliberately never requested.
// Every invocation is fresh. Existing procfs/type/mount/root/child bookends
// remain in their callers. Linux4.9 uses the original fdinfo reader below.
func (r *xraySelectedTCPProc) mountID(ctx context.Context, fd int) (uint64, error) {
	if r == nil || fd < 0 {
		return 0, errXraySelectedTCPRuntime
	}
	if err := xraySelectedTCPFinite(ctx); err != nil {
		return 0, err
	}
	var stat unix.Statx_t
	err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stat)
	return r.mountIDAfterStatx(ctx, fd, stat, err)
}

// Kept separate to exercise old-kernel/denied-syscall paths with real held FDs,
// without a mutable syscall hook or a process-wide capability/result cache.
func (r *xraySelectedTCPProc) mountIDAfterStatx(ctx context.Context, fd int, stat unix.Statx_t, callErr error) (uint64, error) {
	if r == nil || fd < 0 {
		return 0, errXraySelectedTCPRuntime
	}
	if err := xraySelectedTCPFinite(ctx); err != nil {
		return 0, err
	}
	if callErr != nil {
		switch {
		case errors.Is(callErr, unix.ENOSYS), errors.Is(callErr, unix.EOPNOTSUPP), errors.Is(callErr, unix.EINVAL), errors.Is(callErr, unix.EPERM), errors.Is(callErr, unix.EACCES):
			// Absence or denial of the optional observation never grants success.
			// The original protected procfs reader must independently succeed.
			return r.mountIDFromFDInfo(ctx, fd)
		default:
			return 0, errors.Join(errXraySelectedTCPRuntime, callErr)
		}
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 {
		return r.mountIDFromFDInfo(ctx, fd)
	}
	if stat.Mnt_id == 0 {
		return 0, errXraySelectedTCPRuntime
	}
	return stat.Mnt_id, ctx.Err()
}
