package ownedfs

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

var (
	ErrStagedFileChanged = errors.New("owned staged file changed before publication")
	ErrStagedCleanup     = errors.New("owned staged file cleanup was not confirmed")
	ErrRenameAdmission   = errors.New("owned rename admission must complete exactly once")
)

// WriteAtomicWithRenameAdmission stages and syncs the complete file before
// prepared runs. It then verifies the owned temporary file and destination
// paths, and supplies admitRename with a synchronous, one-use rename syscall.
// prepared and cleanup run outside admission; neither callback may reenter the
// owner that called this method. The caller supplies the actual effect admission
// and performs directory sync/readback afterwards. attempted reports whether
// the rename syscall ran, including an uncertain failure. This retains Root's
// descriptor boundary, not protection against root or uncooperative writers.
// ErrStagedCleanup identifies a failure to close/remove the owned stage even
// when no rename was attempted; a clean no-attempt refusal cannot publish data.
func (r *Root) WriteAtomicWithRenameAdmission(name string, data []byte, mode os.FileMode, admitRename func(func() error) error, prepared func() error) (attempted bool, err error) {
	if admitRename == nil {
		return false, ErrRenameAdmission
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
		// Never remove a different inode (including a symlink) that appeared
		// under the temporary name. All cleanup is outside rename admission.
		cleanupErr = errors.Join(cleanupErr, r.removeStagedFile(temporary, created))
		if cleanupErr != nil {
			err = errors.Join(err, ErrStagedCleanup, cleanupErr)
		}
	}()
	if statErr != nil {
		return false, statErr
	}
	if err := f.Chmod(mode); err != nil {
		return false, err
	}
	digest := sha256.Sum256(data)
	if n, err := f.Write(data); err != nil {
		return false, err
	} else if n != len(data) {
		return false, io.ErrShortWrite
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
	if err := r.check(name); err != nil {
		return false, err
	}
	if err := r.verifyStagedFile(temporary, created, mode, int64(len(data)), digest); err != nil {
		return false, err
	}
	return r.admitStagedRename(temporary, name, admitRename)
}

func (r *Root) verifyStagedFile(name string, created os.FileInfo, mode os.FileMode, size int64, digest [32]byte) error {
	info, err := r.Stat(name)
	if err != nil || !sameStagedFile(created, info) || info.Size() != size || runtime.GOOS != "windows" && info.Mode().Perm() != mode.Perm() {
		return errors.Join(ErrStagedFileChanged, err)
	}
	f, err := r.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return errors.Join(ErrStagedFileChanged, err)
	}
	actual, statErr := f.Stat()
	data, readErr := io.ReadAll(io.LimitReader(f, size+1))
	closeErr := f.Close()
	closing, pathErr := r.Stat(name)
	if statErr != nil || readErr != nil || closeErr != nil || pathErr != nil || !sameStagedFile(created, actual) || !sameStagedFile(created, closing) || actual.Size() != size || closing.Size() != size || !actual.ModTime().Equal(closing.ModTime()) || int64(len(data)) != size || sha256.Sum256(data) != digest || runtime.GOOS != "windows" && (actual.Mode().Perm() != mode.Perm() || closing.Mode().Perm() != mode.Perm()) {
		return errors.Join(ErrStagedFileChanged, statErr, readErr, closeErr, pathErr)
	}
	return nil
}

func sameStagedFile(created, current os.FileInfo) bool {
	return created != nil && current != nil && current.Mode().IsRegular() && os.SameFile(created, current)
}

func (r *Root) removeStagedFile(name string, created os.FileInfo) error {
	info, err := r.fs.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !sameStagedFile(created, info) {
		return errors.Join(ErrStagedFileChanged, err)
	}
	if err := r.check(name); err != nil {
		return err
	}
	return r.fs.Remove(name)
}

func (r *Root) admitStagedRename(temporary, name string, admit func(func() error) error) (attempted bool, err error) {
	var mu sync.Mutex
	active, called, repeated := true, false, false
	var renameErr error
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		active = false // Seal even on panic, before the outer cleanup runs.
		attempted = called
		if !called || repeated {
			err = errors.Join(err, ErrRenameAdmission)
		}
		err = errors.Join(err, renameErr) // An admission cannot swallow failure.
	}()
	err = admit(func() error {
		mu.Lock()
		defer mu.Unlock()
		if !active || called {
			repeated = true
			return ErrRenameAdmission
		}
		called = true
		// Only this already-prepared syscall is inside the effect admission.
		if cause := r.fs.Rename(temporary, name); cause != nil {
			renameErr = fmt.Errorf("commit owned transaction: %w", cause)
		}
		return renameErr
	})
	return
}
