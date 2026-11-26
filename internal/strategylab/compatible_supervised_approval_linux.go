//go:build linux

package strategylab

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

// compatibilityProtectedPath checks path ownership separately from approval of
// file bytes. A missing final leaf is permitted for a future state/control file;
// its entire existing parent chain must still be protected.
func compatibilityProtectedPath(path string, allowMissingFile bool) error {
	if !compatibilityCleanPath(path) {
		return errors.New("compatibility protected path must be clean and absolute")
	}
	paths := []string{path}
	for ancestor := filepath.Dir(path); ancestor != paths[len(paths)-1]; ancestor = filepath.Dir(ancestor) {
		paths = append(paths, ancestor)
	}
	slices.Reverse(paths)
	belowTemporary := false
	privateTemporaryParent := false
	for i, current := range paths {
		final := i == len(paths)-1
		info, err := os.Lstat(current)
		if err != nil {
			if final && allowMissingFile && errors.Is(err, os.ErrNotExist) && (!belowTemporary || privateTemporaryParent) {
				return nil
			}
			return fmt.Errorf("compatibility protected path %q: %w", current, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("compatibility path %q has untrusted ownership or is a symlink", current)
		}
		if final {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || (belowTemporary && !privateTemporaryParent) {
				return fmt.Errorf("compatibility file %q is not protected", current)
			}
			return nil
		}
		if !info.IsDir() {
			return fmt.Errorf("compatibility ancestor %q is not a directory", current)
		}
		if belowTemporary {
			if info.Mode().Perm()&0077 != 0 {
				return fmt.Errorf("compatibility temporary descendant %q is not private", current)
			}
			privateTemporaryParent = true
		}
		if info.Mode().Perm()&0022 != 0 {
			if current != "/tmp" || info.Mode()&os.ModeSticky == 0 {
				return fmt.Errorf("compatibility ancestor %q is writable by another user", current)
			}
			belowTemporary = true
		}
	}
	return errors.New("compatibility path has no protected file leaf")
}
