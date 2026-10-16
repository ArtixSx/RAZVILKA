package ownedfs

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// WriteAtomicRetained returns a read-only descriptor of the file this writer
// created. It opens that descriptor before rename and compares the actual
// staged inode; it never adopts a file discovered at the destination later.
// The caller owns the descriptor after success and must sync the directory
// before treating publication as durable. The descriptor grants no runtime,
// effect, admission or ownership authority.
func (r *Root) WriteAtomicRetained(name string, data []byte, mode os.FileMode) (*os.File, error) {
	retained, _, err := r.WriteAtomicRetainedAttempted(name, data, mode)
	return retained, err
}

// WriteAtomicRetainedAttempted also reports whether the rename syscall ran.
// A failure with renameAttempted=false published nothing at name; any other
// failure leaves the destination unknown to the caller.
func (r *Root) WriteAtomicRetainedAttempted(name string, data []byte, mode os.FileMode) (retained *os.File, renameAttempted bool, result error) {
	if err := r.check(name); err != nil {
		return nil, false, err
	}
	temporary := filepath.Join(filepath.Dir(name), ".transaction-"+randomSuffix())
	written, err := r.fs.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return nil, renameAttempted, err
	}
	created, err := written.Stat()
	closed := false
	var read *os.File
	defer func() {
		if !closed {
			result = errors.Join(result, written.Close())
		}
		if result != nil && read != nil {
			result = errors.Join(result, read.Close())
			retained = nil
		}
		if err := r.removeStagedFile(temporary, created); err != nil {
			result = errors.Join(result, ErrStagedCleanup, err)
			if retained != nil {
				result = errors.Join(result, retained.Close())
				retained = nil
			}
		}
	}()
	if err != nil {
		return nil, renameAttempted, err
	}
	if err := written.Chmod(mode); err != nil {
		return nil, renameAttempted, err
	}
	if n, err := written.Write(data); err != nil {
		return nil, renameAttempted, err
	} else if n != len(data) {
		return nil, false, io.ErrShortWrite
	}
	if err := written.Sync(); err != nil {
		return nil, renameAttempted, err
	}
	read, err = r.fs.OpenFile(temporary, os.O_RDONLY, 0)
	if err != nil {
		return nil, renameAttempted, err
	}
	info, err := read.Stat()
	if err != nil || !sameStagedFile(created, info) {
		return nil, renameAttempted, errors.Join(ErrStagedFileChanged, err)
	}
	closed = true
	if err := written.Close(); err != nil {
		return nil, false, errors.Join(ErrStagedCleanup, err)
	}
	if err := r.verifyStagedFile(temporary, created, mode, int64(len(data)), sha256.Sum256(data)); err != nil {
		return nil, renameAttempted, err
	}
	if err := r.check(name); err != nil {
		return nil, renameAttempted, err
	}
	renameAttempted = true
	if err := r.fs.Rename(temporary, name); err != nil {
		return nil, renameAttempted, err
	}
	published, err := r.Stat(name)
	if err != nil || !sameStagedFile(info, published) {
		return nil, renameAttempted, errors.Join(ErrStagedFileChanged, err)
	}
	return read, renameAttempted, nil
}
