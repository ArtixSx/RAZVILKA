package restorejournal

import (
	"errors"
	"io"
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const leaseFile = ".restore.lock"
const leaseMarker = "RAZVILKA private restore writer v1\n"

// The marker is never removed/replaced. Only a kernel lock proves a live
// writer; old/empty/unknown markers require inspection, never PID/age guessing.
func acquireLease(root *ownedfs.Root) (func(), error) {
	return acquireNamedLease(root, leaseFile, leaseMarker)
}

func acquireNamedLease(root *ownedfs.Root, name, marker string) (func(), error) {
	return acquireNamedLeaseWithLock(root, name, marker, lockFile)
}

// A kernel admission refusal happens before any marker or target write. Keep
// that fact separate from invalid metadata and uncertain marker durability.
type leaseLockRefusal struct{ busy bool }

func (e *leaseLockRefusal) Error() string { return e.Unwrap().Error() }
func (e *leaseLockRefusal) Unwrap() error {
	if e.busy {
		return ErrBusy
	}
	return ErrUnavailable
}

func acquireNamedLeaseWithLock(root *ownedfs.Root, name, marker string, lock func(*os.File) error) (func(), error) {
	f, err := openPrivate(root, name, true)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		info, e := root.Stat(name)
		if e != nil || !privateFile(info) || info.Size() != int64(len(marker)) {
			return nil, ErrBusy
		}
		f, err = openPrivate(root, name, false)
	}
	if err != nil {
		return nil, ErrBusy
	}
	keep := false
	defer func() {
		if !keep {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil || !privateFile(info) {
		return nil, ErrBusy
	}
	if err := lock(f); err != nil {
		return nil, &leaseLockRefusal{busy: lockContention(err)}
	}
	current, err := root.Stat(name)
	if err != nil || !os.SameFile(info, current) {
		return nil, ErrBusy
	}
	if created {
		if info.Size() != 0 {
			return nil, ErrBusy
		}
		if n, err := f.WriteString(marker); err != nil || n != len(marker) {
			return nil, ErrBusy
		}
		if f.Sync() != nil || syncJournalDir(root) != nil {
			return nil, ErrBusy
		}
	} else {
		data, err := io.ReadAll(io.LimitReader(f, int64(len(marker))+1))
		if err != nil || string(data) != marker {
			return nil, ErrBusy
		}
	}
	current, err = root.Stat(name)
	if err != nil || !privateFile(current) || !os.SameFile(info, current) || current.Size() != int64(len(marker)) {
		return nil, ErrBusy
	}
	keep = true
	return func() { _ = f.Close() }, nil // Closing releases the kernel lease.
}
