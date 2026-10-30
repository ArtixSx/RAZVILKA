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
// cleanup are outside that admission. A clean refusal without a rename attempt
// preserves ErrAborted (or ErrConflict for a changed image) plus its cause. An
// attempted rename or unconfirmed stage cleanup preserves ErrRecovery. Error
// text exposes no private paths. The same target remains available for repair.
func (f *FileTarget) CompareAndSwapWithRenameAdmission(ctx context.Context, before, after Image, admitRename func(context.Context, func() error) error, prepared ...func() error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrUnavailable
	}
	if err := f.checkExistingLease(); err != nil {
		return err
	}
	if ctx == nil || admitRename == nil || len(prepared) > 1 || !validImage(before) || !validImage(after) || !after.Exists {
		return ErrInvalid
	}
	before, after = clone(before), clone(after)
	current, original, err := f.readPublicationTarget(ctx)
	if err != nil {
		return err
	}
	if !equal(current, before) {
		return ErrConflict
	}
	if equal(before, after) {
		return f.checkExistingLease()
	}
	attempted, err := f.root.WriteAtomicWithRenameAdmission(f.name, after.Data, 0o600, func(rename func() error) error {
		if ctx.Err() != nil {
			return ErrAborted
		}
		if f.existingLease == nil {
			return admitRename(ctx, rename)
		}
		return admitRename(ctx, func() error {
			if err := f.checkExistingLease(); err != nil {
				return err
			}
			if err := f.checkExistingTargetOwner(); err != nil {
				return err
			}
			return rename()
		})
	}, func() error {
		if len(prepared) == 1 && prepared[0] != nil {
			if err := prepared[0](); err != nil {
				return err
			}
		}
		if err := f.checkExistingLease(); err != nil {
			return err
		}
		current, closing, err := f.readPublicationTarget(ctx)
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
		if !attempted && !errors.Is(err, ownedfs.ErrStagedCleanup) {
			kind = ErrAborted
			if errors.Is(err, ErrConflict) || errors.Is(err, ownedfs.ErrStagedFileChanged) {
				kind = ErrConflict
			}
		}
		return &filePublicationError{kind, err}
	}
	if err := f.syncDir(); err != nil {
		return &filePublicationError{ErrRecovery, err}
	}
	current, _, err = f.readPublicationTarget(ctx)
	if err != nil {
		return &filePublicationError{ErrRecovery, err}
	}
	if !equal(current, after) {
		return &filePublicationError{ErrRecovery, ErrConflict}
	}
	if err := f.checkExistingLease(); err != nil {
		return &filePublicationError{ErrRecovery, err}
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
	return readPublicationTargetMode(ctx, root, name, false)
}

func (f *FileTarget) readPublicationTarget(ctx context.Context) (Image, os.FileInfo, error) {
	return readPublicationTargetMode(ctx, f.root, f.name, f.existingLease != nil)
}

func readPublicationTargetMode(ctx context.Context, root *ownedfs.Root, name string, existingOnly bool) (Image, os.FileInfo, error) {
	if ctx.Err() != nil {
		return Image{}, nil, ErrAborted
	}
	info, err := root.Stat(name)
	if errors.Is(err, os.ErrNotExist) {
		return Image{}, nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxImageBytes || existingOnly && !existingOwner(info, false) {
		return Image{}, nil, ErrInvalid
	}
	f, err := openReadOnly(root, name)
	if err != nil {
		return Image{}, nil, ErrUnavailable
	}
	actual, statErr := f.Stat()
	if statErr != nil || !samePublicationFile(info, actual) || !actual.Mode().IsRegular() || existingOnly && !existingOwner(actual, false) {
		_ = f.Close()
		return Image{}, nil, ErrConflict
	}
	data, readErr := io.ReadAll(io.LimitReader(f, MaxImageBytes+1))
	closeErr := f.Close()
	closing, pathErr := root.Stat(name)
	if readErr != nil || closeErr != nil || len(data) > MaxImageBytes {
		return Image{}, nil, ErrInvalid
	}
	if pathErr != nil || !samePublicationFile(actual, closing) || actual.Size() != closing.Size() || !actual.ModTime().Equal(closing.ModTime()) || existingOnly && !existingOwner(closing, false) {
		return Image{}, nil, ErrConflict
	}
	if ctx.Err() != nil {
		return Image{}, nil, ErrAborted
	}
	return Image{Exists: true, Data: data}, actual, nil
}
