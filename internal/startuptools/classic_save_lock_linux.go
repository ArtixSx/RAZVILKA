//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"os"
	"syscall"
)

const classicSaveLockPath = "/run/xtables.lock"

// The researched Ubuntu binary's unchanged default lock path. No caller may
// select another path or replace this held inode during the complete image.
type classicSaveLock struct {
	file         *os.File
	info, parent os.FileInfo
	locked       bool
}

func openClassicSaveLock(ctx context.Context) (*classicSaveLock, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, at("CLASSIC_SAVE_LOCK_CONTEXT", nil)
	}
	parent, err := os.Lstat("/run")
	if err != nil || !parent.IsDir() || !protectedInfo(parent) {
		return nil, at("CLASSIC_SAVE_LOCK_PARENT", err)
	}
	fd, err := syscall.Open(classicSaveLockPath, syscall.O_RDONLY|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, at("CLASSIC_SAVE_LOCK_OPEN", err)
	}
	l := &classicSaveLock{file: os.NewFile(uintptr(fd), classicSaveLockPath), parent: parent}
	l.info, err = l.file.Stat()
	if err == nil {
		err = l.current(ctx)
	}
	if err == nil {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		l.locked = err == nil
	}
	if err == nil {
		err = l.current(ctx)
	}
	if err != nil {
		return nil, at("CLASSIC_SAVE_LOCK", errors.Join(err, l.close()))
	}
	return l, nil
}

func (l *classicSaveLock) current(ctx context.Context) error {
	if l == nil || l.file == nil || l.info == nil || l.parent == nil || ctx == nil || ctx.Err() != nil {
		return at("CLASSIC_SAVE_LOCK_SCOPE", nil)
	}
	info, err := l.file.Stat()
	path, pathErr := os.Lstat(classicSaveLockPath)
	parent, parentErr := os.Lstat("/run")
	if err != nil || pathErr != nil || parentErr != nil || !info.Mode().IsRegular() || !sameNode(l.info, info) || !sameNode(l.info, path) || !sameNode(l.parent, parent) {
		return at("CLASSIC_SAVE_LOCK_CHANGED", errors.Join(err, pathErr, parentErr))
	}
	return ctx.Err()
}

func (l *classicSaveLock) close() error {
	if l == nil || l.file == nil {
		return nil
	}
	var err error
	if l.locked {
		err = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	}
	err = errors.Join(err, l.file.Close())
	l.file, l.locked = nil, false
	return err
}
