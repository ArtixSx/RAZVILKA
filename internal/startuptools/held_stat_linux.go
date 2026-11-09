//go:build linux && (amd64 || arm64)

package startuptools

import (
	"errors"
	"os"
	"sync"
	"syscall"
)

// Scratch only, with one exclusive borrower until Control synchronously joins.
// It stores no file/FD, pathname, expected metadata or observation capability.
type heldStatScratch struct {
	stat    syscall.Stat_t
	err     error
	called  bool
	control func(uintptr)
}

var heldStatScratchPool = sync.Pool{New: func() any {
	s := new(heldStatScratch)
	s.control = func(fd uintptr) {
		s.called = true
		// os.File.Stat's pfd.Fstat ignores EINTR in exactly the same manner.
		for {
			s.err = syscall.Fstat(int(fd), &s.stat)
			if s.err != syscall.EINTR {
				return
			}
		}
	}
	return s
}}

// Observe the SAME held file afresh without allocating an os.FileInfo. Control
// uses os.File's original pfd reference lock; concurrent Close cannot recycle
// the FD under this read. Every caller still performs the surrounding complete
// named-path passes, links, absence and extension-membership checks.
func freshHeldNode(file *os.File, expected os.FileInfo) (bool, error) {
	if file == nil {
		return false, os.ErrInvalid
	}
	if expected == nil {
		return false, nil
	}
	before, ok := expected.Sys().(*syscall.Stat_t)
	if !ok || before == nil {
		return false, nil
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return false, err
	}
	scratch := heldStatScratchPool.Get().(*heldStatScratch)
	scratch.stat, scratch.err, scratch.called = syscall.Stat_t{}, nil, false
	defer func() {
		scratch.stat, scratch.err, scratch.called = syscall.Stat_t{}, nil, false
		heldStatScratchPool.Put(scratch)
	}()
	if err := raw.Control(scratch.control); err != nil {
		// RawControl exposes internal poll errors; retain the ordinary Stat error
		// classification (including os.ErrClosed) on this refusal-only path.
		_, statErr := file.Stat()
		return false, errors.Join(err, statErr)
	}
	if !scratch.called {
		return false, os.ErrInvalid
	}
	if scratch.err != nil {
		return false, &os.PathError{Op: "stat", Path: file.Name(), Err: scratch.err}
	}
	return sameReviewedStat(before, &scratch.stat), nil
}
