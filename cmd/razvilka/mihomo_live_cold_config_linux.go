//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// A read-only held settings image, never a second restore writer lease.
type mihomoLiveColdConfiguration struct {
	self       *mihomoLiveColdConfiguration
	mu         sync.Mutex
	root       *os.Root
	file       *os.File
	path, name string
	info       os.FileInfo
	ancestors  map[string]os.FileInfo
	data       []byte
	closed     bool
	closeErr   error
}

func openMihomoLiveColdConfiguration(ctx context.Context, path string) (out *mihomoLiveColdConfiguration, resultErr error) {
	if ctx == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, dataplane.ErrMihomoLiveRetirement
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(dataplane.ErrMihomoLiveRetirement, err)
	}
	o := &mihomoLiveColdConfiguration{path: path, name: filepath.Base(path), ancestors: map[string]os.FileInfo{}}
	o.self = o
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, o.Close())
			out = nil
		}
	}()
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !mihomoLiveColdConfigDirectory(info) {
			return nil, errors.Join(dataplane.ErrMihomoLiveRetirement, err)
		}
		o.ancestors[parent] = info
		if parent == filepath.Dir(parent) {
			break
		}
	}
	var err error
	o.root, err = os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	before, err := o.root.Lstat(o.name)
	if err != nil || !mihomoLiveColdConfigFile(before) {
		return nil, errors.Join(dataplane.ErrMihomoLiveRetirement, err)
	}
	o.file, err = o.root.OpenFile(o.name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	o.info, err = o.file.Stat()
	if err != nil || !mihomoLiveColdConfigSame(before, o.info, false) {
		return nil, errors.Join(dataplane.ErrMihomoLiveRetirement, err)
	}
	o.data, err = io.ReadAll(io.NewSectionReader(o.file, 0, (4<<20)+1))
	if err != nil || int64(len(o.data)) != o.info.Size() || len(o.data) > 4<<20 {
		return nil, errors.Join(dataplane.ErrMihomoLiveRetirement, err)
	}
	if err := o.Current(ctx); err != nil {
		return nil, err
	}
	return o, nil
}

func (o *mihomoLiveColdConfiguration) Current(ctx context.Context) error {
	if o == nil || o.self != o {
		return dataplane.ErrMihomoLiveRetirement
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.root == nil || o.file == nil || ctx == nil {
		return dataplane.ErrMihomoLiveRetirement
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	bookend := func() error {
		for path, original := range o.ancestors {
			actual, err := os.Lstat(path)
			if err != nil || !mihomoLiveColdConfigSame(original, actual, true) {
				return errors.Join(dataplane.ErrMihomoLiveRetirement, err)
			}
		}
		held, e1 := o.root.Stat(".")
		named, e2 := os.Lstat(filepath.Dir(o.path))
		if e1 != nil || e2 != nil || !mihomoLiveColdConfigSame(o.ancestors[filepath.Dir(o.path)], held, true) || !mihomoLiveColdConfigSame(held, named, true) {
			return errors.Join(dataplane.ErrMihomoLiveRetirement, e1, e2)
		}
		file, e1 := o.file.Stat()
		name, e2 := o.root.Lstat(o.name)
		if e1 != nil || e2 != nil || !mihomoLiveColdConfigSame(o.info, file, false) || !mihomoLiveColdConfigSame(file, name, false) {
			return errors.Join(dataplane.ErrMihomoLiveRetirement, e1, e2)
		}
		return ctx.Err()
	}
	if err := bookend(); err != nil {
		return err
	}
	actual, err := io.ReadAll(io.NewSectionReader(o.file, 0, (4<<20)+1))
	defer clear(actual)
	if err != nil || !bytes.Equal(actual, o.data) {
		return errors.Join(dataplane.ErrMihomoLiveRetirement, err)
	}
	return bookend()
}

func (o *mihomoLiveColdConfiguration) Close() error {
	if o == nil {
		return nil
	}
	if o.self != o {
		return dataplane.ErrMihomoLiveRetirement
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return o.closeErr
	}
	o.closed = true
	clear(o.data)
	o.data = nil
	var err error
	if o.file != nil {
		err = o.file.Close()
	}
	if o.root != nil {
		err = errors.Join(err, o.root.Close())
	}
	o.closeErr = err
	return o.closeErr
}

func mihomoLiveColdConfigDirectory(info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && (info.Mode().Perm()&0022 == 0 || info.Mode()&os.ModeSticky != 0)
}
func mihomoLiveColdConfigFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() <= 0 || info.Size() > 4<<20 {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && s.Nlink == 1
}
func mihomoLiveColdConfigSame(a, b os.FileInfo, directory bool) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Mode() != b.Mode() {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	if !xok || !yok || x.Uid != y.Uid || x.Gid != y.Gid {
		return false
	}
	if directory {
		return mihomoLiveColdConfigDirectory(b)
	}
	return mihomoLiveColdConfigFile(b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && x.Ctim == y.Ctim && x.Nlink == y.Nlink
}
