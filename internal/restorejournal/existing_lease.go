package restorejournal

import (
	"errors"
	"io"
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// existingNamedLease retains the original descriptor and never initializes a
// marker. A path-only preflight followed by the ordinary creator is insufficient:
// an intervening removal must remain a refusal, not manufacture a new owner.
type existingNamedLease struct {
	root           *ownedfs.Root
	path, name     string
	marker         string
	file           *os.File
	rootInfo, info os.FileInfo
	closed         bool
}

func acquireExistingNamedLease(root *ownedfs.Root, path, name, marker string, expectedRoot os.FileInfo) (result *existingNamedLease, resultErr error) {
	rootInfo, err := root.RootInfo()
	if err != nil || !existingOwner(rootInfo, expectedRoot != nil) {
		return nil, ErrUnavailable
	}
	if expectedRoot != nil && (!os.SameFile(expectedRoot, rootInfo) || expectedRoot.Mode() != rootInfo.Mode()) {
		return nil, ErrUnavailable
	}
	f, err := openPrivate(root, name, false)
	if err != nil {
		return nil, ErrBusy
	}
	keep := false
	defer func() {
		if !keep {
			if err := f.Close(); err != nil {
				resultErr = errors.Join(resultErr, ErrUnavailable)
			}
		}
	}()
	info, err := f.Stat()
	if err != nil || !privateFile(info) || !existingOwner(info, true) || info.Size() != int64(len(marker)) {
		return nil, ErrBusy
	}
	if err := lockFile(f); err != nil {
		return nil, &leaseLockRefusal{busy: lockContention(err)}
	}
	lease := &existingNamedLease{root: root, path: path, name: name, marker: marker, file: f, rootInfo: rootInfo, info: info}
	if err := lease.current(); err != nil {
		return nil, err
	}
	keep = true
	return lease, nil
}

func (l *existingNamedLease) current() error {
	if l == nil || l.closed || l.file == nil || l.root == nil {
		return ErrUnavailable
	}
	path, err := os.Lstat(l.path)
	if err != nil || !path.IsDir() || !existingOwner(path, false) || path.Mode() != l.rootInfo.Mode() || !os.SameFile(l.rootInfo, path) {
		return ErrUnavailable
	}
	root, err := l.root.RootInfo()
	if err != nil || !existingOwner(root, false) || root.Mode() != l.rootInfo.Mode() || !os.SameFile(l.rootInfo, root) {
		return ErrUnavailable
	}
	info, err := l.file.Stat()
	if err != nil || !privateFile(info) || !existingOwner(info, true) || info.Mode() != l.info.Mode() || info.Size() != int64(len(l.marker)) || !os.SameFile(l.info, info) {
		return ErrUnavailable
	}
	current, err := l.root.Stat(l.name)
	if err != nil || !privateFile(current) || !existingOwner(current, true) || current.Mode() != info.Mode() || !os.SameFile(info, current) {
		return ErrUnavailable
	}
	data := make([]byte, len(l.marker)+1)
	n, err := l.file.ReadAt(data, 0)
	if n != len(l.marker) || !errors.Is(err, io.EOF) || string(data[:n]) != l.marker {
		return ErrUnavailable
	}
	closing, err := l.root.Stat(l.name)
	if err != nil || !privateFile(closing) || !existingOwner(closing, true) || closing.Mode() != info.Mode() || closing.Size() != int64(len(l.marker)) || !os.SameFile(info, closing) {
		return ErrUnavailable
	}
	return nil
}

// Always release the actual descriptor, including when its path was replaced.
// A closing observation or descriptor error is not a successful clean release.
func (l *existingNamedLease) close() error {
	if l == nil || l.closed {
		return nil
	}
	err := l.current()
	l.closed = true
	if closeErr := l.file.Close(); closeErr != nil {
		err = errors.Join(err, ErrUnavailable)
	}
	return err
}
