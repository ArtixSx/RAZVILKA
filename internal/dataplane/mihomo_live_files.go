package dataplane

import (
	"bytes"
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"io"
	"os"
)

// All identity and config writers use the same original staged-FD protocol.
func publishMihomoLiveFile(ctx context.Context, root *ownedfs.Root, owner *mihomoLiveResource, d *mihomoLiveSidecarIdentityFile) error {
	data := d.data
	for _, path := range []string{d.name, d.temporary} {
		if _, err := root.Stat(path); !errors.Is(err, os.ErrNotExist) {
			return errMihomoLiveMaterial
		}
	}
	written, err := root.OpenFile(d.temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	d.file = written
	info, err := written.Stat()
	d.info = info
	if err == nil {
		var count int
		count, err = written.Write(data)
		if err == nil && count != len(data) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = written.Sync()
	}
	updated, statErr := written.Stat()
	if statErr == nil {
		d.info = updated
	}
	err = errors.Join(err, statErr)
	if err != nil {
		return err
	}
	read, err := root.OpenFile(d.temporary, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	d.file = read
	if closeErr := written.Close(); closeErr != nil {
		return closeErr
	}
	if err := mihomoLiveFileCurrent(root, d, d.temporary); err != nil {
		return err
	}
	if err := owner.currentBeforeStart(ctx); err != nil {
		return err
	}
	if err := owner.control.WithRename(ctx, func() error {
		staged, err := root.Stat(d.temporary)
		if err != nil || !sameMihomoLiveFile(staged, d.info) {
			return errMihomoLiveMaterial
		}
		if _, err := root.Stat(d.name); !errors.Is(err, os.ErrNotExist) {
			return errMihomoLiveMaterial
		}
		if err := root.Rename(d.temporary, d.name); err != nil {
			return err
		}
		d.published = true
		return nil
	}); err != nil {
		return err
	}
	return errors.Join(root.Sync(), mihomoLiveFileCurrent(root, d, d.name))
}
func mihomoLiveFileCurrent(root *ownedfs.Root, d *mihomoLiveSidecarIdentityFile, name string) error {
	if d == nil || d.file == nil || d.info == nil {
		return errMihomoLiveMaterial
	}
	held, err := d.file.Stat()
	named, namedErr := root.Stat(name)
	if err != nil || namedErr != nil || !sameMihomoLiveFile(held, d.info) || !sameMihomoLiveFile(named, d.info) {
		return errMihomoLiveMaterial
	}
	data := make([]byte, len(d.data))
	count, err := d.file.ReadAt(data, 0)
	if err != nil || count != len(data) || !bytes.Equal(data, d.data) {
		return errMihomoLiveMaterial
	}
	return nil
}

func sameMihomoLiveFile(original, current os.FileInfo) bool {
	return original != nil && current != nil && current.Mode().IsRegular() && os.SameFile(original, current) && original.Size() == current.Size() && original.Mode() == current.Mode() && original.ModTime().Equal(current.ModTime())
}

func removeMihomoLiveFile(ctx context.Context, root *ownedfs.Root, d *mihomoLiveSidecarIdentityFile, remove func(func() error) error) error {
	if d == nil {
		return nil
	}
	for _, name := range []string{d.name, d.temporary} {
		info, err := root.Stat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || d.info == nil || !sameMihomoLiveFile(info, d.info) {
			return errMihomoLiveMaterial
		}
		if d.file == nil {
			return errMihomoLiveMaterial
		}
		held, err := d.file.Stat()
		if err != nil || !sameMihomoLiveFile(held, d.info) {
			return errMihomoLiveMaterial
		}
		if err := remove(func() error {
			actual, err := root.Stat(name)
			if err != nil || !sameMihomoLiveFile(actual, d.info) {
				return errMihomoLiveMaterial
			}
			return root.Remove(name)
		}); err != nil {
			return err
		}
	}
	if err := root.Sync(); err != nil {
		return err
	}
	if d.file != nil {
		if err := d.file.Close(); err != nil {
			return err
		}
		d.file = nil
	}
	clear(d.data)
	return ctx.Err()
}
