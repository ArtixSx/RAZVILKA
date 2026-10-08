package restorejournal

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// CompareAndSwapWithRenameAdmission retains this target's existing writer lease
// and mutex through staging, exact comparison, publication and readback. Only
// publication of an existing after-image is supported; deletion/unknown-image
// repair use ordinary CompareAndSwap. At most one optional prepared hook runs
// after temporary file Sync and before the final before-image/inode checks.
// Callbacks must not reenter this target. admitRename receives the original ctx
// and must invoke only the supplied synchronous, one-use rename under the
// caller's actual control admission. Staging, directory Sync, readback and
// cleanup are outside that admission. A failure after rename was attempted is
// uncertain and preserves ErrRecovery plus its cause, without exposing private
// paths in the error text. The same target remains available for exact repair.
func (f *FileTarget) CompareAndSwapWithRenameAdmission(ctx context.Context, before, after Image, admitRename func(context.Context, func() error) error, prepared ...func() error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrUnavailable
	}
	if ctx == nil || admitRename == nil || len(prepared) > 1 || !validImage(before) || !validImage(after) || !after.Exists {
		return ErrInvalid
	}
	before, after = clone(before), clone(after)
	current, original, err := readPublicationTarget(ctx, f.root, f.name)
	if err != nil {
		return err
	}
	if !equal(current, before) {
		return ErrConflict
	}
	if equal(before, after) {
		return nil
	}
	attempted, err := f.root.WriteAtomicWithRenameAdmission(f.name, after.Data, 0o600, func(rename func() error) error {
		if ctx.Err() != nil {
			return ErrAborted
		}
		return admitRename(ctx, rename)
	}, func() error {
		if len(prepared) == 1 && prepared[0] != nil {
			if err := prepared[0](); err != nil {
				return err
			}
		}
		current, closing, err := readPublicationTarget(ctx, f.root, f.name)
		if err != nil {
			return err
		}
		if !equal(current, before) || !samePublicationFile(original, closing) {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		kind := ErrRecovery
		if !attempted {
			switch {
			case errors.Is(err, ErrConflict), errors.Is(err, ownedfs.ErrStagedFileChanged):
				kind = ErrConflict
			case errors.Is(err, ErrAborted), ctx.Err() != nil:
				kind = ErrAborted
			}
		}
		return &filePublicationError{kind, err}
	}
	if err := f.syncDir(); err != nil {
		return &filePublicationError{ErrRecovery, err}
	}
	current, _, err = readPublicationTarget(ctx, f.root, f.name)
	if err != nil {
		return &filePublicationError{ErrRecovery, err}
	}
	if !equal(current, after) {
		return &filePublicationError{ErrRecovery, ErrConflict}
	}
	return nil
}

type filePublicationError struct{ kind, cause error }

func (e *filePublicationError) Error() string    { return e.kind.Error() }
func (e *filePublicationError) GoString() string { return e.kind.Error() }
func (e *filePublicationError) Unwrap() []error  { return []error{e.kind, e.cause} }

func samePublicationFile(before, after os.FileInfo) bool {
	if before == nil || after == nil {
		return before == nil && after == nil
	}
	return os.SameFile(before, after) && before.Mode() == after.Mode()
}

// Retain the actual target inode alongside the exact bytes. A same-byte path
// replacement during staging is still a conflicting independently owned file.
func readPublicationTarget(ctx context.Context, root *ownedfs.Root, name string) (Image, os.FileInfo, error) {
	if ctx.Err() != nil {
		return Image{}, nil, ErrAborted
	}
	info, err := root.Stat(name)
	if errors.Is(err, os.ErrNotExist) {
		return Image{}, nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxImageBytes {
		return Image{}, nil, ErrInvalid
	}
	f, err := openReadOnly(root, name)
	if err != nil {
		return Image{}, nil, ErrUnavailable
	}
	actual, statErr := f.Stat()
	if statErr != nil || !samePublicationFile(info, actual) || !actual.Mode().IsRegular() {
		_ = f.Close()
		return Image{}, nil, ErrConflict
	}
	data, readErr := io.ReadAll(io.LimitReader(f, MaxImageBytes+1))
	closeErr := f.Close()
	closing, pathErr := root.Stat(name)
	if readErr != nil || closeErr != nil || len(data) > MaxImageBytes {
		return Image{}, nil, ErrInvalid
	}
	if pathErr != nil || !samePublicationFile(actual, closing) || actual.Size() != closing.Size() || !actual.ModTime().Equal(closing.ModTime()) {
		return Image{}, nil, ErrConflict
	}
	if ctx.Err() != nil {
		return Image{}, nil, ErrAborted
	}
	return Image{Exists: true, Data: data}, actual, nil
}
