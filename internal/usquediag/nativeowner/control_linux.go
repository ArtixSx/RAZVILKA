//go:build linux

package nativeowner

import (
	"context"
	"io"
	"os"
)

// Held descriptors of the EXISTING control ABI, not another record or grant.
// The original CORE lease still issues all forward admission.
type controlAnchors struct {
	root               *os.Root
	directory, lock    *os.File
	rootInfo, lockInfo os.FileInfo
	path               string
}

func openControlAnchors(ctx context.Context, c Control) (*controlAnchors, error) {
	if ctx.Err() != nil || protectedPath(c.Root, true) != nil || protectedPath(c.Root+string(os.PathSeparator)+".control.lock", true) != nil {
		return nil, ErrOwned
	}
	a := &controlAnchors{path: c.Root}
	var err error
	a.root, err = os.OpenRoot(c.Root)
	if err != nil {
		return nil, ErrOwned
	}
	a.directory, err = a.root.Open(".")
	if err == nil {
		a.rootInfo, err = a.directory.Stat()
	}
	if err == nil {
		a.lock, err = a.root.Open(".control.lock")
	}
	if err == nil {
		a.lockInfo, err = a.lock.Stat()
	}
	if err != nil || a.current() != nil {
		_ = a.close()
		return nil, ErrOwned
	}
	return a, nil
}
func (a *controlAnchors) current() error {
	if a == nil || a.directory == nil || a.lock == nil {
		return ErrOwned
	}
	root, e1 := os.Lstat(a.path)
	openedRoot, e2 := a.directory.Stat()
	lock, e3 := a.root.Lstat(".control.lock")
	openedLock, e4 := a.lock.Stat()
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || root.Mode()&os.ModeSymlink != 0 || root.Mode().Perm()&0o077 != 0 || !lock.Mode().IsRegular() || lock.Mode().Perm()&0o077 != 0 || !os.SameFile(root, a.rootInfo) || !os.SameFile(openedRoot, a.rootInfo) || !os.SameFile(lock, a.lockInfo) || !os.SameFile(openedLock, a.lockInfo) {
		return ErrOwned
	}
	marker, err := io.ReadAll(io.NewSectionReader(a.lock, 0, 128))
	if err != nil || string(marker) != "RAZVILKA control authority v1\n" {
		return ErrOwned
	}
	return nil
}
func (a *controlAnchors) close() error {
	var failed bool
	if a.lock != nil {
		failed = a.lock.Close() != nil || failed
	}
	if a.directory != nil {
		failed = a.directory.Close() != nil || failed
	}
	if a.root != nil {
		failed = a.root.Close() != nil || failed
	}
	if failed {
		return ErrOwned
	}
	return nil
}
