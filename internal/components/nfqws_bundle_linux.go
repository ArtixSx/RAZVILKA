//go:build linux

package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func syncBundleFile(f *os.File) error       { return f.Sync() }
func chmodBundleDirectory(f *os.File) error { return f.Chmod(0555) }

func publishManagedNFQWS(ctx context.Context, directory, stage, generation string, admission func(func() error) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	fd, err := root.Open(".")
	if err != nil {
		return err
	}
	defer fd.Close()
	staged, err := root.Open(stage)
	if err != nil {
		return err
	}
	defer staged.Close()
	if err := admission(func() error {
		if err := staged.Chmod(0555); err != nil {
			return err
		}
		if err := unix.Renameat2(int(fd.Fd()), stage, int(fd.Fd()), generation, unix.RENAME_NOREPLACE); err != nil {
			return errors.Join(err, staged.Chmod(0700))
		}
		return nil
	}); err != nil {
		return err
	}
	return staged.Sync()
}

// NFQWS drops UID before Lua/blob reads. Check all canonical ancestors without
// relaxing existing permissions. Actual ACL/UID access is still a native probe.
func publicManagedNFQWSPath(path string) error {
	for {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0001 == 0 {
			return errors.Join(ErrManagedNFQWSBundle, err)
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}
