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
	f, err := openPrivate(root, leaseFile, true)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		info, e := root.Stat(leaseFile)
		if e != nil || !privateFile(info) || info.Size() != int64(len(leaseMarker)) {
			return nil, ErrBusy
		}
		f, err = openPrivate(root, leaseFile, false)
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
	if err != nil || !privateFile(info) || lockFile(f) != nil {
		return nil, ErrBusy
	}
	current, err := root.Stat(leaseFile)
	if err != nil || !os.SameFile(info, current) {
		return nil, ErrBusy
	}
	if created {
		if info.Size() != 0 {
			return nil, ErrBusy
		}
		if n, err := f.WriteString(leaseMarker); err != nil || n != len(leaseMarker) {
			return nil, ErrBusy
		}
		if f.Sync() != nil || syncJournalDir(root) != nil {
			return nil, ErrBusy
		}
	} else {
		data, err := io.ReadAll(io.LimitReader(f, int64(len(leaseMarker))+1))
		if err != nil || string(data) != leaseMarker {
			return nil, ErrBusy
		}
	}
	current, err = root.Stat(leaseFile)
	if err != nil || !privateFile(current) || !os.SameFile(info, current) || current.Size() != int64(len(leaseMarker)) {
		return nil, ErrBusy
	}
	keep = true
	return func() { _ = f.Close() }, nil // Closing releases the kernel lease.
}
