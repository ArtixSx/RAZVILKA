//go:build linux

package updatecheck

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func reviewProductionDaemonPath() (func() error, error) {
	return reviewOwnedDaemonPath("/opt/sbin/start-stop-daemon", "/opt/bin/busybox", "/")
}

// Entware installs this one applet as an absolute BusyBox alias. This does not
// authorize symlinks in configuration, installer destinations or other tools.
// Every production layout admission takes a new review; no cached permission
// survives a changed alias/target or bypasses the ordinary helper-role checks.
func reviewOwnedDaemonPath(alias, busybox, boundary string) (func() error, error) {
	refuse := func() (func() error, error) { return nil, errors.New("unsafe-owner-or-path") }
	initial, err := os.Lstat(alias)
	if err != nil {
		return refuse()
	}
	linked := initial.Mode()&os.ModeSymlink != 0
	inspect := func() (os.FileInfo, error) {
		if linked {
			if checkOwnedAncestors(filepath.Dir(alias), boundary) != nil {
				return nil, errors.New("unsafe-owner-or-path")
			}
			link, err := os.Lstat(alias)
			if err != nil {
				return nil, err
			}
			owner, ok := link.Sys().(*syscall.Stat_t)
			target, err := os.Readlink(alias)
			if !ok || owner.Uid != 0 || link.Mode()&os.ModeSymlink == 0 || err != nil || target != busybox || !filepath.IsAbs(target) || checkOwnedAncestors(busybox, boundary) != nil {
				return nil, errors.New("unsafe-owner-or-path")
			}
		} else if checkOwnedAncestors(alias, boundary) != nil {
			return nil, errors.New("unsafe-owner-or-path")
		}
		path := alias
		if linked {
			path = busybox
		}
		file, err := os.Lstat(path)
		if err != nil || !file.Mode().IsRegular() || file.Mode().Perm()&0100 == 0 {
			return nil, errors.New("unsafe-owner-or-path")
		}
		return file, nil
	}
	target, err := inspect()
	if err != nil {
		return refuse()
	}
	current := func() error {
		link, err := os.Lstat(alias)
		if err != nil || !os.SameFile(initial, link) || initial.Mode() != link.Mode() {
			return errors.New("unsafe-owner-or-path")
		}
		file, err := inspect()
		if err != nil || !os.SameFile(target, file) || target.Mode() != file.Mode() {
			return errors.New("unsafe-owner-or-path")
		}
		final, err := os.Lstat(alias)
		if err != nil || !os.SameFile(initial, final) || initial.Mode() != final.Mode() {
			return errors.New("unsafe-owner-or-path")
		}
		return nil
	}
	if current() != nil {
		return refuse()
	}
	return current, nil
}
