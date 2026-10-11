package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Each FD is handed over by the SAME original writer that staged its inode,
// renamed it and fsynced its directory. No pathname reread constructs this.
type xraySelectedTCPExecutionRecords struct {
	mu                sync.Mutex
	scope             *executionResourceScope
	root              *ownedfs.Root
	anchor            os.FileInfo
	transactionRoot   *ownedfs.Root
	transactionAnchor os.FileInfo
	files             [2]*os.File
	infos             [2]os.FileInfo
	images            [2][]byte
	closed            bool
	replacement       atomic.Pointer[xraySelectedTCPReplacement]
}

// Private sink called by CORE's actual two journal writers. Caller holds the
// original scope metadata lock or the serialized original Manager operation.
// FD ownership transfers only on success; a failed second publication retains
// the first actual authored inode rather than adopting a matching replacement.
func (s *executionResourceScope) captureOriginalXrayExecutionRecord(index int, file *os.File, info os.FileInfo, canonical []byte) error {
	if s == nil || index < 0 || index > 1 || file == nil || info == nil || len(canonical) == 0 || len(canonical) > 16<<20 || len(s.xraySelectedTCP) != 1 {
		return ErrExecutionJournal
	}
	var r *XraySelectedTCPExecutionResource
	for _, resource := range s.xraySelectedTCP {
		r = resource
	}
	if r == nil || r.self != r || r.scope != s || r.records == nil || r.records.scope != s {
		return ErrExecutionJournal
	}
	d := r.records
	root, name := d.recordPath(index)
	return d.captureOriginalRecord(index, file, info, canonical, root, name)
}

func (d *xraySelectedTCPExecutionRecords) recordPath(index int) (*ownedfs.Root, string) {
	if index == 0 {
		return d.transactionRoot, "execution.json"
	}
	if p := d.replacement.Load(); p != nil && p.self == p && p.prior != nil && p.prior.records == d && p.priorAlias.Load() {
		return d.transactionRoot, "replacement-execution.json"
	}
	return d.root, "latest-execution.json"
}

func (d *xraySelectedTCPExecutionRecords) captureOriginalRecord(index int, file *os.File, info os.FileInfo, canonical []byte, root *ownedfs.Root, name string) error {
	if d == nil || d.scope == nil || root == nil || file == nil || info == nil || index < 0 || index > 1 {
		return ErrExecutionJournal
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.root == nil {
		return ErrExecutionJournal
	}
	expected, err := json.Marshal(d.scope.execution)
	var compact bytes.Buffer
	if err != nil || json.Compact(&compact, canonical) != nil || !bytes.Equal(expected, compact.Bytes()) {
		return ErrExecutionJournal
	}
	held, err := file.Stat()
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
		_ = d.files[index].Close()
	}
	d.files[index], d.infos[index], d.images[index] = file, held, bytes.Clone(expected)
	return nil
}

func (d *xraySelectedTCPExecutionRecords) current(ctx context.Context, complete bool) error {
	if d == nil || d.scope == nil || d.root == nil || xraySelectedTCPFinite(ctx) != nil {
		return ErrExecutionJournal
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.currentLocked(ctx, complete, false)
}

// Original writer bookend before either publication, never a path adoption.
// Zero slots are possible only before the actual first publication ACK; after
// any native version/run attempt both original writer FDs must already exist.
func (d *xraySelectedTCPExecutionRecords) beforePublication() error {
	if d == nil || d.scope == nil || d.root == nil {
		return ErrExecutionJournal
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	allowMissing := true
	for _, r := range d.scope.xraySelectedTCP {
		if r == nil || r.records != d || r.versionUsed || r.startUsed || r.startACK {
			allowMissing = false
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	return d.currentLocked(ctx, false, allowMissing)
}

func (d *xraySelectedTCPExecutionRecords) currentLocked(ctx context.Context, complete, allowMissing bool) error {
	if d.closed {
		return ErrExecutionJournal
	}
	anchor, err := os.Lstat(d.scope.managerRoot)
	if err != nil || !networkPolicyPrivateDirectory(anchor) || !os.SameFile(d.anchor, anchor) {
		return ErrExecutionJournal
	}
	transaction, err := os.Lstat(d.scope.root)
	if err != nil || d.transactionRoot == nil || !networkPolicyPrivateDirectory(transaction) || !os.SameFile(d.transactionAnchor, transaction) {
		return ErrExecutionJournal
	}
	if complete && (len(d.images[0]) == 0 || !bytes.Equal(d.images[0], d.images[1])) {
		return ErrExecutionJournal
	}
	for i := range 2 {
		root, name := d.recordPath(i)
		if d.files[i] == nil || d.infos[i] == nil || len(d.images[i]) == 0 {
			if allowMissing && d.files[i] == nil && d.infos[i] == nil && len(d.images[i]) == 0 {
				continue
			}
			return ErrExecutionJournal
		}
		before, err := d.files[i].Stat()
		named, namedErr := root.Stat(name)
		detached := false
		if i == 1 {
			if p := d.replacement.Load(); p != nil && p.self == p && p.prior != nil && p.prior.records == d && !p.priorAlias.Load() && p.handedOver.Load() {
				detached = p.latestCurrent(ctx) == nil
			}
		}
		if err != nil || namedErr != nil || !validNetworkPolicyReceiptFile(before) || !os.SameFile(before, d.infos[i]) || !detached && !os.SameFile(before, named) || before.Size() != d.infos[i].Size() || before.Mode() != d.infos[i].Mode() || !before.ModTime().Equal(d.infos[i].ModTime()) || before.Size() <= 0 || before.Size() > 16<<20 {
			return ErrExecutionJournal
		}
		data := make([]byte, int(before.Size()))
		n, readErr := d.files[i].ReadAt(data, 0)
		var compact bytes.Buffer
		after, statErr := root.Stat(name)
		closing := statErr == nil && os.SameFile(after, before)
		heldAfter, heldErr := d.files[i].Stat()
		closing = closing && heldErr == nil && os.SameFile(heldAfter, before) && heldAfter.Size() == before.Size() && heldAfter.Mode() == before.Mode() && heldAfter.ModTime().Equal(before.ModTime())
		if detached {
			p := d.replacement.Load()
			closing = heldErr == nil && os.SameFile(heldAfter, before) && heldAfter.Size() == before.Size() && heldAfter.Mode() == before.Mode() && heldAfter.ModTime().Equal(before.ModTime()) && p != nil && p.latestCurrent(ctx) == nil
		}
		if readErr != nil || n != len(data) || !closing || json.Compact(&compact, data) != nil || !bytes.Equal(compact.Bytes(), d.images[i]) {
			return ErrExecutionJournal
		}
	}
	return ctx.Err()
}

func (d *xraySelectedTCPExecutionRecords) close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	var err error
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
	return err
}
