//go:build linux

package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"golang.org/x/sys/unix"
)

func nativeValidateMihomoProfile(parent context.Context, artifacts string, image restorejournal.Image, data []byte, start func(context.Context, func() error) error) (err error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	fd, err := unix.MemfdCreate("razvilka-mihomo-profile", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return err
	}
	profile := os.NewFile(uintptr(fd), "razvilka-mihomo-profile")
	defer func() { err = errors.Join(err, profile.Close()) }()
	if _, err := profile.Write(data); err != nil {
		return err
	}
	if _, err := profile.Seek(0, 0); err != nil {
		return err
	}
	if _, err := unix.FcntlInt(profile.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return err
	}
	// A fresh private home prevents native validation from reading/writing any
	// installed Mihomo cache. It is inherited by FD and removed only if its
	// original parent/name/inode still match after the sole Wait.
	parentRoot, err := ownedfs.Open(os.TempDir())
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, parentRoot.Close()) }()
	name, err := parentRoot.MkdirTemp(".", ".razvilka-mihomo-validate-")
	if err != nil {
		return err
	}
	initial, err := parentRoot.Stat(name)
	if err != nil {
		return err
	}
	directory, err := parentRoot.OpenFile(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() {
		named, e := parentRoot.Stat(name)
		held, h := directory.Stat()
		if e != nil || h != nil || !os.SameFile(initial, named) || !os.SameFile(initial, held) {
			err = errors.Join(err, restorejournal.ErrConflict, e, h)
		} else {
			err = errors.Join(err, parentRoot.RemoveAll(name))
		}
		err = errors.Join(err, directory.Close())
	}()
	if filepath.Base(name) == "." || initial.Mode().Perm() != 0700 {
		return restorejournal.ErrConflict
	}
	return withMihomoArtifact(ctx, artifacts, image, func(ctx context.Context, binary *os.File) error {
		out, err := runHeldMihomoCommand(ctx, binary, []*os.File{profile, directory}, []string{"-t", "-f", "/proc/self/fd/4", "-d", "/proc/self/fd/5"}, start)
		clear(out)
		return err
	})
}
