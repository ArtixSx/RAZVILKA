//go:build linux

package components

import (
	"context"
	"errors"
	"fmt"
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
	original, err := staged.Stat()
	if err != nil {
		return err
	}
	// Seal and sync before short publication admission. UpdateStarted already
	// accepts this exact immutable stage after a crash; no generation is visible.
	if err := staged.Chmod(0555); err != nil {
		return err
	}
	if err := staged.Sync(); err != nil {
		return err
	}
	if fault != nil {
		if err := fault("after:bundle-stage-chmod"); err != nil {
			return err // preserve the exact sealed-stage crash cut
		}
	}
	published := false
	if err := admission(func() error {
		renameErr := unix.Renameat2(int(fd.Fd()), stage, int(fd.Fd()), generation, unix.RENAME_NOREPLACE)
		published = renameErr == nil
		return renameErr
	}); err != nil {
		if !published {
			// A known refusal restores only our still-held unpublished stage.
			// A rename followed by an admission error keeps the generation sealed.
			return errors.Join(err, staged.Chmod(original.Mode().Perm()), staged.Sync())
		}
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

func managedNFQWSNodeDescription(info os.FileInfo) string {
	if info == nil {
		return "unavailable metadata"
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "unavailable UID"
	}
	return fmt.Sprintf("UID=%d EUID=%d mode=%04o; production requires UID/EUID0 and no group/other write", owner.Uid, os.Geteuid(), info.Mode().Perm())
}
