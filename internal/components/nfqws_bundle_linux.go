//go:build linux

package components

import (
	"context"
	"os"

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
	return admission(func() error {
		return unix.Renameat2(int(fd.Fd()), stage, int(fd.Fd()), generation, unix.RENAME_NOREPLACE)
	})
}
