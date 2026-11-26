package ownedfs

import (
	"errors"
	"io"
	"os"
)

// ReadDir reads at most limit entries from the original held directory, not
// from its configured pathname. It adds no permission to open or mutate the
// root through OpenFile. A replaced pathname cannot redirect or block this read.
func (r *Root) ReadDir(limit int) ([]os.DirEntry, error) {
	if r == nil || r.fs == nil || limit < 1 || limit > 1024 {
		return nil, errors.New("bounded original directory read required")
	}
	f, err := r.fs.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := f.ReadDir(limit)
	if readErr == io.EOF {
		readErr = nil // Normal end must not mask a simultaneous Close error.
	}
	return entries, errors.Join(readErr, f.Close())
}

// ReadDirAt enumerates a descendant through the original held root. OpenRoot
// opens only a directory, so a concurrent replacement by a FIFO or device
// cannot turn a bounded namespace observation into a blocking file read.
func (r *Root) ReadDirAt(name string, limit int) ([]os.DirEntry, error) {
	if r == nil || r.fs == nil || limit < 1 || limit > 1024 {
		return nil, errors.New("bounded descendant directory read required")
	}
	if err := r.check(name); err != nil {
		return nil, err
	}
	before, err := r.fs.Lstat(name)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("real descendant directory required")
	}
	child, err := r.fs.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	defer child.Close()
	held, err := child.Stat(".")
	if err != nil || !os.SameFile(before, held) {
		return nil, errors.New("descendant directory changed while opening")
	}
	f, err := child.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := f.ReadDir(limit)
	if readErr == io.EOF {
		readErr = nil
	}
	closeErr := f.Close()
	after, err := r.fs.Lstat(name)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("descendant directory changed while reading")
	}
	return entries, errors.Join(readErr, closeErr)
}
