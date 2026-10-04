//go:build linux

package components

import (
	"context"
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func syncBundleFile(f *os.File) error       { return f.Sync() }
func chmodBundleDirectory(f *os.File) error { return f.Chmod(0555) }

func publishManagedNFQWS(ctx context.Context, directory, stage, generation string, admission func(func() error) error, fault func(string) error) error {
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
		if fault != nil {
			if err := fault("after:bundle-stage-chmod"); err != nil {
				return err // simulate the crash cut: preserve the sealed stage
			}
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

func trustedManagedNFQWSOwner(info os.FileInfo, fixture bool) error {
	owner, ok := info.Sys().(*syscall.Stat_t)
	euid := os.Geteuid()
	if !ok || euid < 0 || (!fixture && euid != 0) || owner.Uid != uint32(euid) || info.Mode().Perm()&0022 != 0 {
		return ErrManagedNFQWSBundle
	}
	return nil
}

func managedNFQWSPublicTraversal(info os.FileInfo) bool { return info.Mode().Perm()&0001 != 0 }
