//go:build linux

package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func commitOfflinePriorReplacement(ctx context.Context, item *offlinePriorReplacement, admit func(func() error) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return admit(func() error { return renameOfflinePriorReplacement(item) })
}

// Only retained fd/leaf metadata and one rename syscall occur under the
// current control admission. Staging, hashes, waits and fsync are outside it.
func renameOfflinePriorReplacement(item *offlinePriorReplacement) error {
	if item == nil || item.parent == nil || item.parentInfo == nil || item.parentFD == nil {
		return ErrPairedOfflineRestore
	}
	parent, err := item.parent.Stat(".")
	opened, openedErr := item.parentFD.Stat()
	current, currentErr := os.Lstat(item.parent.Name())
	if err != nil || openedErr != nil || currentErr != nil || !os.SameFile(item.parentInfo, parent) || !os.SameFile(item.parentInfo, opened) || !os.SameFile(item.parentInfo, current) || !safePriorSourceInfo(current) {
		return ErrPairedOfflineRestore
	}
	name := filepath.Base(filepath.FromSlash(item.path))
	_, oldExists := item.before[item.path]
	_, newExists := item.after[item.path]
	if oldExists {
		var old os.FileInfo
		for _, observation := range item.seen {
			if filepath.ToSlash(observation.path) == item.path {
				old = observation.info
			}
		}
		actual, err := item.parent.Lstat(name)
		if err != nil || old == nil || !samePriorInfo(old, actual) {
			return ErrPairedOfflineRestore
		}
	} else if _, err := item.parent.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return ErrPairedOfflineRestore
	}
	if newExists {
		actual, err := item.parent.Lstat(item.stage)
		if err != nil || !samePriorInfo(item.staged, actual) {
			return ErrPairedOfflineRestore
		}
	}
	fd := item.parentFD
	switch {
	case oldExists && newExists:
		return unix.Renameat2(int(fd.Fd()), item.stage, int(fd.Fd()), name, unix.RENAME_EXCHANGE)
	case newExists:
		return unix.Renameat2(int(fd.Fd()), item.stage, int(fd.Fd()), name, unix.RENAME_NOREPLACE)
	case oldExists:
		return unix.Renameat2(int(fd.Fd()), name, int(fd.Fd()), item.stage, unix.RENAME_NOREPLACE)
	default:
		return nil
	}
}
