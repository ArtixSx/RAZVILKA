//go:build linux

package dataplane

import (
	"errors"
	"strconv"

	"golang.org/x/sys/unix"
)

// The same fresh legacy mount ID adapter already used by netidentity and the
// selected-TCP observer. Linux fs/stat.c and fs/proc/fd.c expose the same
// real_mount(file->f_path.mnt)->mnt_id. Never request MNT_ID_UNIQUE or cache a
// result. Existing root, named/held FD, namespace, birth, thread and closing
// checks remain unchanged; old kernels retain the protected fdinfo path.
func (p *linuxInactiveProcPass) mountID(fd int) (string, error) {
	if err := p.valid(); err != nil {
		return "", err
	}
	if fd < 0 {
		return "", ErrProxyRuntimeInactive
	}
	if err := p.basicFD(p.fdinfo, unix.S_IFDIR); err != nil {
		return "", err
	}
	var stat unix.Statx_t
	err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stat)
	return p.mountIDResult(fd, stat, err)
}

// Separate result handling tests optional-syscall failures using real held
// descriptors, without installing a mutable syscall hook in the observer.
func (p *linuxInactiveProcPass) mountIDAfterStatx(fd int, stat unix.Statx_t, callErr error) (string, error) {
	if err := p.valid(); err != nil {
		return "", err
	}
	if fd < 0 {
		return "", ErrProxyRuntimeInactive
	}
	if err := p.basicFD(p.fdinfo, unix.S_IFDIR); err != nil {
		return "", err
	}
	return p.mountIDResult(fd, stat, callErr)
}

// Both callers validate fdinfo once before the optional syscall/result path.
func (p *linuxInactiveProcPass) mountIDResult(fd int, stat unix.Statx_t, callErr error) (string, error) {
	if err := p.valid(); err != nil {
		return "", err
	}
	if callErr != nil {
		switch {
		case errors.Is(callErr, unix.ENOSYS), errors.Is(callErr, unix.EOPNOTSUPP), errors.Is(callErr, unix.EINVAL), errors.Is(callErr, unix.EPERM), errors.Is(callErr, unix.EACCES):
			return p.readMountIDFromFDInfo(fd)
		default:
			return "", errors.Join(ErrProxyRuntimeInactive, callErr)
		}
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 {
		return p.readMountIDFromFDInfo(fd)
	}
	if stat.Mnt_id == 0 {
		return "", ErrProxyRuntimeInactive
	}
	return strconv.FormatUint(stat.Mnt_id, 10), p.ctx.Err()
}
