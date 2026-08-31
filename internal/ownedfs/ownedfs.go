// Package ownedfs confines mutation to an explicitly opened application-owned
// directory. It rejects root deletion, traversal and symlinks. os.Root also
// enforces the boundary if a descendant is replaced after a path check.
package ownedfs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Root struct{ fs *os.Root }

func Open(path string) (*Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) == filepath.VolumeName(path)+string(filepath.Separator) {
		return nil, errors.New("owned root must be an absolute non-filesystem-root directory")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("owned root must be a real directory")
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	after, err := r.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		_ = r.Close()
		return nil, errors.New("owned root changed while opening")
	}
	return &Root{fs: r}, nil
}

func (r *Root) Close() error { return r.fs.Close() }

// Check is useful before handing paths to a runtime. It is not a sandbox for
// that runtime; mutations performed here additionally use descriptor anchoring.
func (r *Root) Check(name string) error { return r.check(name) }

func (r *Root) Stat(name string) (os.FileInfo, error) {
	if err := r.check(name); err != nil {
		return nil, err
	}
	return r.fs.Stat(name)
}

func (r *Root) OpenFile(name string, flag int, mode os.FileMode) (*os.File, error) {
	if err := r.check(name); err != nil {
		return nil, err
	}
	return r.fs.OpenFile(name, flag, mode)
}

func (r *Root) ReadLimited(name string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("positive owned read limit required")
	}
	f, err := r.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("owned file is not regular")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("owned file exceeds read limit")
	}
	return data, nil
}

func (r *Root) check(name string) error {
	if !filepath.IsLocal(name) || filepath.Clean(name) == "." {
		return errors.New("owned target must be strictly below its root")
	}
	current := ""
	for _, part := range strings.Split(filepath.Clean(name), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := r.fs.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink in owned target")
		}
	}
	return nil
}

func (r *Root) Remove(name string) error {
	if err := r.check(name); err != nil {
		return err
	}
	return r.fs.Remove(name)
}

func (r *Root) RemoveAll(name string) error {
	if err := r.check(name); err != nil {
		return err
	}
	return r.fs.RemoveAll(name)
}

func (r *Root) MkdirAll(name string, mode os.FileMode) error {
	if err := r.check(name); err != nil {
		return err
	}
	return r.fs.MkdirAll(name, mode)
}

func randomSuffix() string {
	var data [16]byte
	// crypto/rand.Read fails closed on operating-system entropy failure.
	_, _ = rand.Read(data[:])
	return hex.EncodeToString(data[:])
}

// MkdirTemp returns a relative name, to be removed through the same Root.
func (r *Root) MkdirTemp(parent, prefix string) (string, error) {
	if prefix == "" || strings.ContainsAny(prefix, "/\\\x00") {
		return "", errors.New("invalid owned temporary prefix")
	}
	name := filepath.Join(parent, prefix+randomSuffix())
	if err := r.check(name); err != nil {
		return "", err
	}
	if err := r.fs.Mkdir(name, 0o700); err != nil {
		return "", err
	}
	return name, nil
}

func (r *Root) WriteAtomic(name string, data []byte, mode os.FileMode) error {
	if err := r.check(name); err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(name), ".transaction-"+randomSuffix())
	f, err := r.fs.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close(); _ = r.fs.Remove(temporary) }()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := r.check(name); err != nil {
		return err
	}
	if err := r.fs.Rename(temporary, name); err != nil {
		return fmt.Errorf("commit owned transaction: %w", err)
	}
	return nil
}
