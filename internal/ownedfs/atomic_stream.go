package ownedfs

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const MaxAtomicArtifactBytes = 256 << 20

type contextStream struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextStream) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// WriteAtomicStreamWithRenameAdmission copies an already authenticated artifact
// with bounded memory. Size and digest are mandatory; the caller retains the
// original source FD and its ownership checks through prepared/readback. It
// uses the same original staged inode and one-use rename boundary as byte CAS.
// This does not expand private journal image limits or authorize an artifact.
func (r *Root) WriteAtomicStreamWithRenameAdmission(ctx context.Context, name string, source io.Reader, size int64, digest [32]byte, mode os.FileMode, admitRename func(func() error) error, prepared func() error) (attempted bool, result error) {
	if ctx == nil || source == nil || admitRename == nil || size < 1 || size > MaxAtomicArtifactBytes {
		return false, ErrRenameAdmission
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := r.check(name); err != nil {
		return false, err
	}
	temporary := filepath.Join(filepath.Dir(name), ".transaction-"+randomSuffix())
	f, err := r.fs.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return false, err
	}
	created, statErr := f.Stat()
	closed := false
	defer func() {
		var cleanupErr error
		if !closed {
			cleanupErr = f.Close()
		}
		cleanupErr = errors.Join(cleanupErr, r.removeStagedFile(temporary, created))
		if cleanupErr != nil {
			result = errors.Join(result, ErrStagedCleanup, cleanupErr)
		}
	}()
	if statErr != nil {
		return false, statErr
	}
	if err := f.Chmod(mode); err != nil {
		return false, err
	}
	hash := sha256.New()
	n, err := io.CopyBuffer(io.MultiWriter(f, hash), io.LimitReader(contextStream{ctx, source}, size+1), make([]byte, 64<<10))
	if err != nil {
		return false, err
	}
	if n != size || string(hash.Sum(nil)) != string(digest[:]) {
		return false, ErrStagedFileChanged
	}
	if err := f.Sync(); err != nil {
		return false, err
	}
	closed = true
	if err := f.Close(); err != nil {
		return false, errors.Join(ErrStagedCleanup, err)
	}
	if prepared != nil {
		if err := prepared(); err != nil {
			return false, err
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := r.check(name); err != nil {
		return false, err
	}
	if err := r.verifyStagedFile(temporary, created, mode, size, digest); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return r.admitStagedRename(temporary, name, admitRename)
}
