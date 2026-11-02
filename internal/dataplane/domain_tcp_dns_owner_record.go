package dataplane

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// The original writer, retained from the very first protected DNS owner
// publication. Decoded bytes or a reopened equal image never reconstruct it.
type domainTCPDNSOwnerRecord struct {
	self                     *domainTCPDNSOwnerRecord
	root                     *ownedfs.Root
	directory                *os.File
	file                     *os.File
	anchor, info             os.FileInfo
	path, destination        string
	canonical                []byte
	attempted, moved, synced bool
	closeIndex               int
	beforeClose              func(int) // Private deterministic original FD close fault seam.
	closeErr                 error
	syncDirectory            func() error
	rename                   func(*os.File, string, string) error
}

func retainDomainTCPDNSOwnerRecord(root *ownedfs.Root, path string, file *os.File, data []byte, planID string) (*domainTCPDNSOwnerRecord, error) {
	if root == nil || file == nil || !validExecutionPlanID(planID) {
		return nil, ErrDomainPolicyTCPConsumer
	}
	anchor, err := root.RootInfo()
	if err != nil {
		return nil, err
	}
	opened, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	directory, err := opened.Open(".")
	closeErr := opened.Close()
	if err != nil || closeErr != nil {
		if directory != nil {
			directory.Close()
		}
		return nil, errors.Join(err, closeErr)
	}
	info, err := file.Stat()
	if err != nil {
		directory.Close()
		return nil, err
	}
	r := &domainTCPDNSOwnerRecord{root: root, directory: directory, file: file, anchor: anchor, info: info, path: path, destination: "retired-" + planID + "-owner.json", canonical: bytes.Clone(data), rename: domainTCPDNSOwnerRenameNoReplace}
	r.self = r
	r.syncDirectory = directory.Sync
	if err := r.current("owner.json"); err != nil {
		directory.Close()
		return nil, err
	}
	return r, nil
}

func (r *domainTCPDNSOwnerRecord) current(name string) error {
	if r == nil || r.self != r || r.root == nil || r.directory == nil || r.file == nil || r.anchor == nil || r.info == nil || len(r.canonical) == 0 || len(r.canonical) > 128<<10 {
		return ErrDomainPolicyTCPConsumer
	}
	before, err := os.Lstat(r.path)
	held, e2 := r.root.RootInfo()
	dir, e3 := r.directory.Stat()
	if err != nil || e2 != nil || e3 != nil || !domainTCPDNSOwnerDirectory(before) || !os.SameFile(r.anchor, before) || !os.SameFile(r.anchor, held) || !os.SameFile(r.anchor, dir) {
		return errors.Join(ErrDomainPolicyTCPConsumer, err, e2, e3)
	}
	info, err := r.file.Stat()
	named, e2 := os.Lstat(filepath.Join(r.path, name))
	if err != nil || e2 != nil || !domainTCPDNSOwnerPrivateFile(info) || !domainTCPDNSOwnerPrivateFile(named) || !os.SameFile(r.info, info) || !os.SameFile(info, named) || info.Size() != int64(len(r.canonical)) || !info.ModTime().Equal(r.info.ModTime()) {
		return errors.Join(ErrDomainPolicyTCPConsumer, err, e2)
	}
	data := make([]byte, len(r.canonical)+1)
	n, err := r.file.ReadAt(data, 0)
	if err != nil && !errors.Is(err, io.EOF) || n != len(r.canonical) || !bytes.Equal(data[:n], r.canonical) {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	after, e1 := r.file.Stat()
	last, e2 := os.Lstat(filepath.Join(r.path, name))
	root, e3 := os.Lstat(r.path)
	if e1 != nil || e2 != nil || e3 != nil || !domainTCPDNSOwnerPrivateFile(after) || !domainTCPDNSOwnerPrivateFile(last) || !domainTCPDNSOwnerDirectory(root) || !os.SameFile(info, after) || !os.SameFile(after, last) || !os.SameFile(r.anchor, root) || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return errors.Join(ErrDomainPolicyTCPConsumer, e1, e2, e3)
	}
	return nil
}

// Move into retained history with no replacement. An uncertain syscall is
// retried only after observing BOTH original source and reserved destination;
// foreign occupants are never overwritten or removed.
func (r *domainTCPDNSOwnerRecord) retire(ctx context.Context) error {
	if r == nil || r.self != r || xraySelectedTCPFinite(ctx) != nil || r.syncDirectory == nil {
		return ErrDomainPolicyTCPConsumer
	}
	if r.closeErr != nil {
		return r.closeErr
	}
	if !r.moved {
		_, sourceErr := os.Lstat(filepath.Join(r.path, "owner.json"))
		_, destinationErr := os.Lstat(filepath.Join(r.path, r.destination))
		if r.attempted && errors.Is(sourceErr, os.ErrNotExist) && destinationErr == nil {
			if err := r.current(r.destination); err != nil {
				return err
			}
			r.moved = true
		} else {
			if sourceErr != nil || !errors.Is(destinationErr, os.ErrNotExist) {
				return errors.Join(ErrDomainPolicyTCPConsumer, sourceErr, destinationErr)
			}
			if err := r.current("owner.json"); err != nil {
				return err
			}
			if r.rename == nil {
				return ErrDomainPolicyTCPConsumer
			}
			r.attempted = true
			if err := r.rename(r.directory, "owner.json", r.destination); err != nil {
				return err
			}
			if err := r.current(r.destination); err != nil {
				return err
			}
			if _, err := os.Lstat(filepath.Join(r.path, "owner.json")); !errors.Is(err, os.ErrNotExist) {
				return errors.Join(ErrDomainPolicyTCPConsumer, err)
			}
			r.moved = true
		}
	}
	if err := r.current(r.destination); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(r.path, "owner.json")); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	if !r.synced {
		if err := r.syncDirectory(); err != nil {
			return err
		}
		r.synced = true
	}
	return ctx.Err()
}
func (r *domainTCPDNSOwnerRecord) close() error {
	if r == nil || r.self != r || !r.moved || !r.synced {
		return ErrDomainPolicyTCPConsumer
	}
	if r.closeErr != nil {
		return r.closeErr
	}
	for r.closeIndex < 3 {
		if r.beforeClose != nil {
			r.beforeClose(r.closeIndex)
		}
		var err error
		switch r.closeIndex {
		case 0:
			err = r.file.Close()
		case 1:
			err = r.directory.Close()
		case 2:
			err = r.root.Close()
		}
		if err != nil {
			r.closeErr = errors.Join(ErrPolicyAdditionUnknown, err)
			return r.closeErr
		}
		r.closeIndex++
	}
	return nil
}
