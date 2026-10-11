package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func wgFiniteContext(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrWGOperationOwner
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return ErrWGOperationOwner
	}
	return nil
}

func newWGExecutionRecords(s *executionResourceScope) (*wgExecutionRecords, error) {
	if s == nil || s.wgOwner == nil || s.wgOwner.scope != s || s.root != filepath.Join(s.managerRoot, "transactions", s.execution.PlanID) {
		return nil, ErrWGOperationOwner
	}
	root, anchor, err := openNetworkPolicyObservationRoot(s.managerRoot)
	if err != nil {
		return nil, err
	}
	transaction, transactionAnchor, err := openNetworkPolicyObservationRoot(s.root)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	rootInfo, rootErr := root.RootInfo()
	transactionInfo, transactionErr := transaction.RootInfo()
	if rootErr != nil || transactionErr != nil || !os.SameFile(anchor, rootInfo) || !os.SameFile(transactionAnchor, transactionInfo) {
		return nil, errors.Join(ErrExecutionJournal, rootErr, transactionErr, root.Close(), transaction.Close())
	}
	return &wgExecutionRecords{scope: s, root: root, anchor: anchor, transactionRoot: transaction, transactionAnchor: transactionAnchor}, nil
}

// Each FD is handed over by the SAME original writer that staged and renamed
// its inode. Directory durability is a separate ACK; no path reread creates it.
type wgExecutionRecords struct {
	mu                sync.Mutex
	scope             *executionResourceScope
	root              *ownedfs.Root
	anchor            os.FileInfo
	transactionRoot   *ownedfs.Root
	transactionAnchor os.FileInfo
	files             [2]*os.File
	infos             [2]os.FileInfo
	images            [2][]byte
	ack               [2]bool
	syncDirectory     func(*ownedfs.Root) error
	closed            bool
	closeErr          error
}

// Private sink called by CORE's actual two journal writers. Caller holds the
// original scope metadata lock or the serialized original Manager operation.
// FD ownership transfers only on success; a failed second publication retains
// the first actual authored inode rather than adopting a matching replacement.
func (s *executionResourceScope) captureOriginalWGExecutionRecord(index int, file *os.File, info os.FileInfo, canonical []byte) error {
	if s == nil || index < 0 || index > 1 || file == nil || info == nil || len(canonical) == 0 || len(canonical) > 16<<20 || s.wgRecords == nil {
		return ErrExecutionJournal
	}
	d := s.wgRecords
	if d.scope != s {
		return ErrExecutionJournal
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.root == nil {
		return ErrExecutionJournal
	}
	if err := d.currentRoots(); err != nil {
		return err
	}
	expected, err := json.Marshal(s.execution)
	var compact bytes.Buffer
	if err != nil || json.Compact(&compact, canonical) != nil || !bytes.Equal(expected, compact.Bytes()) {
		return ErrExecutionJournal
	}
	held, err := file.Stat()
	root := d.transactionRoot
	name := "execution.json"
	if index == 1 {
		root, name = d.root, "latest-execution.json"
	}
	named, statErr := root.Stat(name)
	if err != nil || statErr != nil || !validNetworkPolicyReceiptFile(held) || !os.SameFile(info, held) || !os.SameFile(held, named) || held.Size() <= 0 || held.Size() > 16<<20 {
		return ErrExecutionJournal
	}
	data := make([]byte, int(held.Size()))
	defer clear(data)
	n, readErr := file.ReadAt(data, 0)
	compact.Reset()
	if readErr != nil || n != len(data) || json.Compact(&compact, data) != nil || !bytes.Equal(compact.Bytes(), expected) {
		return ErrExecutionJournal
	}
	if d.files[index] != nil {
		d.closeErr = errors.Join(d.closeErr, d.files[index].Close())
	}
	d.files[index], d.infos[index], d.images[index], d.ack[index] = file, held, bytes.Clone(expected), false
	return nil
}

// Transfer the actual renamed inode before the directory durability ACK. A
// failed sync keeps this original FD available to physical cleanup only.
func (d *wgExecutionRecords) publishOriginal(index int, data []byte) error {
	root, name := d.transactionRoot, "execution.json"
	if index == 1 {
		root, name = d.root, "latest-execution.json"
	}
	file, err := root.WriteAtomicRetained(name, data, 0600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err == nil {
		err = d.scope.captureOriginalWGExecutionRecord(index, file, info, data)
	}
	if err != nil {
		return errors.Join(err, file.Close())
	}
	syncDirectory := d.syncDirectory
	if syncDirectory == nil {
		syncDirectory = syncDataplaneJournalDirectory
	}
	if err := syncDirectory(root); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.files[index] != file {
		return ErrExecutionJournal
	}
	d.ack[index] = true
	return d.closeErr
}

func (d *wgExecutionRecords) current(ctx context.Context, complete bool) error {
	if d == nil || d.scope == nil || d.root == nil || wgFiniteContext(ctx) != nil {
		return ErrExecutionJournal
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.currentLocked(ctx, complete, false)
}

// Original writer bookend before either publication, never a path adoption.
// Zero slots are possible only before the actual first publication ACK; after
// any native version/run attempt both original writer FDs must already exist.
func (d *wgExecutionRecords) beforePublication() error {
	if d == nil || d.scope == nil || d.root == nil {
		return ErrExecutionJournal
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	allowMissing := d.files[0] == nil && d.files[1] == nil
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	return d.currentLocked(ctx, false, allowMissing)
}

func (d *wgExecutionRecords) currentLocked(ctx context.Context, complete, allowMissing bool) error {
	if d.closed {
		return ErrExecutionJournal
	}
	if err := d.currentRoots(); err != nil {
		return err
	}
	if complete && (d.closeErr != nil || !d.ack[0] || !d.ack[1] || len(d.images[0]) == 0 || !bytes.Equal(d.images[0], d.images[1])) {
		return ErrExecutionJournal
	}
	for i, root := range []*ownedfs.Root{d.transactionRoot, d.root} {
		if d.files[i] == nil || d.infos[i] == nil || len(d.images[i]) == 0 {
			if allowMissing && d.files[i] == nil && d.infos[i] == nil && len(d.images[i]) == 0 {
				continue
			}
			return ErrExecutionJournal
		}
		name := []string{"execution.json", "latest-execution.json"}[i]
		before, err := d.files[i].Stat()
		named, namedErr := root.Stat(name)
		if err != nil || namedErr != nil || !validNetworkPolicyReceiptFile(before) || !os.SameFile(before, d.infos[i]) || !os.SameFile(before, named) || before.Size() != d.infos[i].Size() || before.Mode() != d.infos[i].Mode() || !before.ModTime().Equal(d.infos[i].ModTime()) || before.Size() <= 0 || before.Size() > 16<<20 {
			return ErrExecutionJournal
		}
		data := make([]byte, int(before.Size()))
		n, readErr := d.files[i].ReadAt(data, 0)
		var compact bytes.Buffer
		after, statErr := root.Stat(name)
		if readErr != nil || n != len(data) || statErr != nil || !os.SameFile(after, before) || json.Compact(&compact, data) != nil || !bytes.Equal(compact.Bytes(), d.images[i]) {
			return ErrExecutionJournal
		}
	}
	return errors.Join(ctx.Err(), d.currentRoots())
}

func (d *wgExecutionRecords) currentRoots() error {
	for _, entry := range []struct {
		path   string
		root   *ownedfs.Root
		anchor os.FileInfo
	}{{d.scope.managerRoot, d.root, d.anchor}, {d.scope.root, d.transactionRoot, d.transactionAnchor}} {
		if entry.root == nil || entry.anchor == nil {
			return ErrExecutionJournal
		}
		named, err := os.Lstat(entry.path)
		held, heldErr := entry.root.RootInfo()
		if err != nil || heldErr != nil || !networkPolicyPrivateDirectory(named) || !networkPolicyPrivateDirectory(held) || !os.SameFile(entry.anchor, named) || !os.SameFile(entry.anchor, held) {
			return errors.Join(ErrExecutionJournal, err, heldErr)
		}
	}
	return nil
}

func (d *wgExecutionRecords) close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return d.closeErr
	}
	d.closed = true
	err := d.closeErr
	for _, file := range d.files {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
	}
	if d.root != nil {
		err = errors.Join(err, d.root.Close())
	}
	if d.transactionRoot != nil {
		err = errors.Join(err, d.transactionRoot.Close())
	}
	d.closeErr = err
	return d.closeErr
}
