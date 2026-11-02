//go:build linux

package dataplane

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Historical bytes only. No source/process/effect ownership is issued here;
// the offline operation independently retains its original roots and guards.
func readMihomoColdFile(root *os.Root, name string) ([]byte, error) {
	if err := mihomoColdFilePath(root, name); err != nil {
		return nil, err
	}
	before, err := root.Lstat(name)
	if err != nil {
		return nil, errors.Join(ErrMihomoLiveRetirement, err)
	}
	return readMihomoColdFileAt(root, name, before)
}

func readMihomoColdFileAt(root *os.Root, name string, expected os.FileInfo) (data []byte, resultErr error) {
	if err := mihomoColdFilePath(root, name); err != nil {
		return nil, err
	}
	before, err := root.Lstat(name)
	if err != nil || !mihomoColdFileSame(expected, before) {
		return nil, errors.Join(ErrMihomoLiveRetirement, err)
	}
	file, err := openMihomoColdFile(root, name)
	if err != nil {
		return nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
		if resultErr != nil {
			clear(data)
			data = nil
			resultErr = errors.Join(ErrMihomoLiveRetirement, resultErr)
		}
	}()
	opened, err := file.Stat()
	if err != nil || !mihomoColdFileSame(expected, opened) {
		return nil, errors.Join(ErrMihomoLiveRetirement, err)
	}
	data, err = io.ReadAll(io.LimitReader(file, bootRetirementLimit+1))
	if err != nil || len(data) > bootRetirementLimit || int64(len(data)) != opened.Size() {
		return data, errors.Join(ErrMihomoLiveRetirement, err)
	}
	after, e1 := file.Stat()
	named, e2 := root.Lstat(name)
	if err := mihomoColdFilePath(root, name); err != nil {
		return data, err
	}
	if e1 != nil || e2 != nil || !mihomoColdFileSame(expected, after) || !mihomoColdFileSame(after, named) {
		return data, errors.Join(ErrMihomoLiveRetirement, e1, e2)
	}
	return data, nil
}

// NONBLOCK prevents a regular-file→FIFO race from blocking before fstat;
// NOFOLLOW and the original root confine even a swapped final component.
func openMihomoColdFile(root *os.Root, name string) (*os.File, error) {
	if err := mihomoColdFilePath(root, name); err != nil {
		return nil, err
	}
	before, err := root.Lstat(name)
	if err != nil || !mihomoColdFileValid(before) {
		return nil, errors.Join(ErrMihomoLiveRetirement, err)
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.Join(ErrMihomoLiveRetirement, err)
	}
	opened, e1 := file.Stat()
	named, e2 := root.Lstat(name)
	pathErr := mihomoColdFilePath(root, name)
	if e1 != nil || e2 != nil || pathErr != nil || !mihomoColdFileSame(before, opened) || !mihomoColdFileSame(opened, named) {
		return nil, errors.Join(ErrMihomoLiveRetirement, e1, e2, pathErr, file.Close())
	}
	return file, nil
}

func mihomoColdFileValid(info os.FileInfo) bool {
	return info != nil && executionHistoryOwner(info, false) && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && info.Mode().Perm()&0077 == 0 && info.Size() >= 0 && info.Size() <= bootRetirementLimit
}

func mihomoColdFileSame(a, b os.FileInfo) bool {
	if !mihomoColdFileValid(a) || !mihomoColdFileValid(b) || !os.SameFile(a, b) || a.Size() != b.Size() || a.Mode() != b.Mode() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Ctim == y.Ctim && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink
}

func mihomoColdFilePath(root *os.Root, name string) error {
	if root == nil || !filepath.IsLocal(name) || filepath.Clean(name) != name || name == "." {
		return ErrMihomoLiveRetirement
	}
	info, err := root.Stat(".")
	if err != nil || !networkPolicyPrivateDirectory(info) || !executionHistoryOwner(info, true) {
		return errors.Join(ErrMihomoLiveRetirement, err)
	}
	part := ""
	components := strings.Split(name, string(filepath.Separator))
	for _, component := range components[:len(components)-1] {
		part = filepath.Join(part, component)
		info, err := root.Lstat(part)
		if err != nil || !networkPolicyPrivateDirectory(info) || !executionHistoryOwner(info, true) {
			return errors.Join(ErrMihomoLiveRetirement, err)
		}
	}
	return nil
}
