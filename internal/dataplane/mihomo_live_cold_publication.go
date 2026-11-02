package dataplane

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

// An offline author retains the descriptor it actually created. The caller
// updates its record slot before syncing the directory, including lost ACKs.
// current closes the old-image CAS after staging/fsync and before rename.
func writeMihomoColdRetained(root *os.Root, name string, data []byte, current func() error) (file *os.File, resultErr error) {
	if root == nil || current == nil || name != "execution.json" && name != "latest-execution.json" && name != "retirement.json" && name != "completed.json" || len(data) == 0 || len(data) > bootRetirementLimit {
		return nil, ErrMihomoLiveRetirement
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	temporary := ".mihomo-retirement-" + hex.EncodeToString(nonce[:])
	f, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	created, err := f.Stat()
	transferred := false
	defer func() {
		if !transferred {
			resultErr = errors.Join(resultErr, f.Close())
		}
		if info, err := root.Lstat(temporary); err == nil {
			if created == nil || !os.SameFile(created, info) {
				resultErr = errors.Join(resultErr, ErrMihomoLiveRetirement)
				return
			}
			resultErr = errors.Join(resultErr, root.Remove(temporary))
		} else if !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	if err != nil {
		return nil, err
	}
	if n, err := f.Write(data); err != nil || n != len(data) {
		return nil, errors.Join(err, io.ErrShortWrite)
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := current(); err != nil {
		return nil, err
	}
	named, err := root.Lstat(temporary)
	held, heldErr := f.Stat()
	if err != nil || heldErr != nil || !os.SameFile(created, named) || !os.SameFile(created, held) || !executionHistoryOwner(held, false) || held.Mode().Perm() != 0600 || held.Size() != int64(len(data)) {
		return nil, ErrMihomoLiveRetirement
	}
	actual := make([]byte, len(data))
	defer clear(actual)
	if n, err := f.ReadAt(actual, 0); err != nil || n != len(actual) || !bytes.Equal(actual, data) {
		return nil, ErrMihomoLiveRetirement
	}
	if err := root.Rename(temporary, name); err != nil {
		return nil, err
	}
	// From this point the original caller retains the new inode even if the
	// subsequent name comparison or durability acknowledgment reports failure.
	transferred = true
	named, err = root.Lstat(name)
	if err != nil || !os.SameFile(held, named) {
		return f, ErrMihomoLiveRetirement
	}
	return f, nil
}

type mihomoColdRecord struct {
	root *os.Root
	name string
	file *os.File
	info os.FileInfo
	data []byte
}

func openMihomoColdRecord(root *os.Root, name string, data []byte) (*mihomoColdRecord, error) {
	f, err := openMihomoColdFile(root, name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	r := &mihomoColdRecord{root: root, name: name, file: f, info: info, data: bytes.Clone(data)}
	if err := r.current(); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return r, nil
}

func (r *mihomoColdRecord) current() error {
	if r == nil || r.file == nil || r.root == nil || r.info == nil {
		return ErrMihomoLiveRetirement
	}
	before, err := r.file.Stat()
	named, nameErr := r.root.Lstat(r.name)
	if err != nil || nameErr != nil || !os.SameFile(before, r.info) || !os.SameFile(named, r.info) || !executionHistoryOwner(before, false) || before.Mode().Perm() != 0600 || before.Size() != int64(len(r.data)) || before.Mode() != r.info.Mode() || !before.ModTime().Equal(r.info.ModTime()) {
		return ErrMihomoLiveRetirement
	}
	raw := make([]byte, len(r.data))
	defer clear(raw)
	n, readErr := r.file.ReadAt(raw, 0)
	closing, closeErr := r.root.Lstat(r.name)
	held, heldErr := r.file.Stat()
	if readErr != nil || n != len(raw) || !bytes.Equal(raw, r.data) || closeErr != nil || heldErr != nil || mihomoColdFileIdentity(closing) != mihomoColdFileIdentity(before) || mihomoColdFileIdentity(held) != mihomoColdFileIdentity(before) {
		return ErrMihomoLiveRetirement
	}
	return nil
}

func (r *mihomoColdRecord) publish(data []byte, current func() error) error {
	f, err := writeMihomoColdRetained(r.root, r.name, data, current)
	if f == nil {
		return err
	}
	old := r.file
	r.file, r.data = f, bytes.Clone(data)
	var statErr error
	r.info, statErr = f.Stat()
	return errors.Join(err, statErr, old.Close(), syncBootRetirementDirectory(r.root, "."), r.current())
}
