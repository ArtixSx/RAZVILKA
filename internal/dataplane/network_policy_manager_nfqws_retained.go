package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Only successful original Apply retains this owner. Decoded ACTIVE records
// never create it, and its resources do not alias the returned execution DTO.
type retainedNFQWSExecution struct {
	self      *retainedNFQWSExecution
	scope     *executionResourceScope
	execution *nfqws2ActiveExecution
	root      *ownedfs.Root
	anchor    os.FileInfo
	mu        sync.Mutex
	files     [2]*os.File
	infos     [2]os.FileInfo
	image     []byte
}

type nfqwsRetainedOperation struct {
	self    *nfqwsRetainedOperation
	owner   *retainedNFQWSExecution
	cleanup *operationgate.ExclusiveCleanupReview
	forward bool
	open    atomic.Bool
}
type nfqwsRetainedOperationKey struct{}

func (s *executionResourceScope) retainedOperation(ctx context.Context) (*nfqwsRetainedOperation, error) {
	if ctx == nil || ctx.Err() != nil || !s.retained || s.retainedOwner == nil || s.retainedOwner.self != s.retainedOwner || s.retainedOwner.scope != s {
		return nil, ErrNFQWSScopedOwner
	}
	o, ok := ctx.Value(nfqwsRetainedOperationKey{}).(*nfqwsRetainedOperation)
	if !ok || o == nil || o.self != o || !o.open.Load() || o.owner != s.retainedOwner {
		return nil, ErrNFQWSScopedOwner
	}
	return o, nil
}

func (s *executionResourceScope) prepareActiveNFQWS(ctx context.Context) error {
	e, ok := ctx.Value(nfqws2ActiveExecutionKey{}).(*nfqws2ActiveExecution)
	if !ok || e == nil || e.self != e || e.resource == nil || e.resource.scope != s || e.resource.finalOwner == nil {
		return ErrNFQWSScopedOwner
	}
	r := e.resource
	if err := e.health(ctx); err != nil {
		return err
	}
	observed, err := r.finalOwner.Current(ctx)
	if err != nil || r.finalOwner.VerifyOwnerObservation(ctx, observed) != nil {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := r.matching(r.binding)
	if err != nil || s.execution.Resources[i].Phase != "transfer-ack" || !r.transferACK {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := r.check(ctx, true); err != nil {
		return err
	}
	copy := observed
	s.execution.Resources[i].NFQWS.Observation = &copy
	s.execution.Resources[i].State, s.execution.Resources[i].Phase = "active", "active"
	return nil
}

func (m *Manager) retainActiveNFQWS(ctx context.Context, s *executionResourceScope) (result error) {
	e, ok := ctx.Value(nfqws2ActiveExecutionKey{}).(*nfqws2ActiveExecution)
	if !ok || e == nil || e.self != e || e.resource == nil || e.resource.scope != s || s.execution.State != "committed" {
		return ErrNFQWSScopedOwner
	}
	if err := e.health(ctx); err != nil {
		return err
	}
	root, anchor, err := openNetworkPolicyObservationRoot(m.StateRoot)
	if err != nil {
		return err
	}
	o := &retainedNFQWSExecution{scope: s, execution: e, root: root, anchor: anchor}
	o.self = o
	defer func() {
		if result != nil {
			o.closeRecords()
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateExecutionResources(*s.execution, true); err != nil {
		return err
	}
	if err := o.captureRecords(); err != nil {
		return err
	}
	data, err := json.Marshal(s.execution)
	if err != nil {
		return err
	}
	var detached Execution
	if err := json.Unmarshal(data, &detached); err != nil {
		return err
	}
	m.retainedNFQMu.Lock()
	defer m.retainedNFQMu.Unlock()
	if m.retainedNFQ != nil {
		return ErrNFQWSScopedOwner
	}
	s.execution, s.retained, s.retainedOwner = &detached, true, o
	m.retainedNFQ = o
	return nil
}

// Capture only the images written by the original existing BOTH writers.
// This is an in-memory FD bookend, never another ledger or receipt grant.
func (o *retainedNFQWSExecution) captureRecords() (result error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	data, err := json.Marshal(o.scope.execution)
	if err != nil {
		return executionJournalError(err)
	}
	var files [2]*os.File
	var infos [2]os.FileInfo
	defer func() {
		if result != nil {
			for _, f := range files {
				if f != nil {
					f.Close()
				}
			}
		}
	}()
	for i, root := range []*ownedfs.Root{o.scope.owned, o.root} {
		name := []string{"execution.json", "latest-execution.json"}[i]
		files[i], err = root.OpenFile(name, os.O_RDONLY, 0)
		if err != nil {
			return executionJournalError(err)
		}
		infos[i], err = files[i].Stat()
		if err != nil || !validNetworkPolicyReceiptFile(infos[i]) {
			return ErrExecutionJournal
		}
		actual, readErr := io.ReadAll(io.LimitReader(files[i], (16<<20)+1))
		var compact bytes.Buffer
		current, statErr := root.Stat(name)
		if readErr != nil || statErr != nil || len(actual) > 16<<20 || json.Compact(&compact, actual) != nil || !bytes.Equal(compact.Bytes(), data) || !os.SameFile(infos[i], current) {
			return ErrExecutionJournal
		}
	}
	for _, f := range o.files {
		if f != nil {
			f.Close()
		}
	}
	o.files, o.infos, o.image = files, infos, data
	return nil
}

func (o *retainedNFQWSExecution) recordsCurrent() error {
	if o == nil || o.self != o || o.root == nil {
		return ErrExecutionJournal
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	anchor, err := os.Lstat(o.scope.managerRoot)
	if err != nil || !networkPolicyPrivateDirectory(anchor) || !os.SameFile(o.anchor, anchor) {
		return ErrExecutionJournal
	}
	for i, root := range []*ownedfs.Root{o.scope.owned, o.root} {
		name := []string{"execution.json", "latest-execution.json"}[i]
		if o.files[i] == nil || o.infos[i] == nil {
			return ErrExecutionJournal
		}
		held, err := o.files[i].Stat()
		if err != nil || !validNetworkPolicyReceiptFile(held) || !os.SameFile(o.infos[i], held) {
			return ErrExecutionJournal
		}
		current, err := root.Stat(name)
		if err != nil || !validNetworkPolicyReceiptFile(current) || !os.SameFile(o.infos[i], current) {
			return ErrExecutionJournal
		}
		data, err := root.ReadLimited(name, 16<<20)
		var compact bytes.Buffer
		after, statErr := root.Stat(name)
		if err != nil || statErr != nil || json.Compact(&compact, data) != nil || !bytes.Equal(compact.Bytes(), o.image) || !os.SameFile(current, after) {
			return ErrExecutionJournal
		}
	}
	return nil
}

func (o *retainedNFQWSExecution) closeRecords() {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, f := range o.files {
		if f != nil {
			f.Close()
		}
	}
	if o.root != nil {
		o.root.Close()
	}
}

func (m *Manager) retainedNFQOwner() *retainedNFQWSExecution {
	m.retainedNFQMu.Lock()
	defer m.retainedNFQMu.Unlock()
	return m.retainedNFQ
}

func (m *Manager) checkRetainedNFQWSRecord(record Execution) error {
	active := false
	for _, r := range record.Resources {
		active = active || r.State == "active"
	}
	if !active {
		return nil
	}
	o := m.retainedNFQOwner()
	if o == nil || o.self != o || o.scope == nil {
		return ErrNFQWSScopedOwner
	}
	o.scope.mu.Lock()
	defer o.scope.mu.Unlock()
	if !o.scope.open || !o.scope.retained || o.scope.retainedOwner != o || !reflect.DeepEqual(*o.scope.execution, record) {
		return ErrNFQWSScopedOwner
	}
	return o.recordsCurrent()
}

func (o *retainedNFQWSExecution) operation(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview, forward bool) (context.Context, func(), error) {
	if ctx == nil || ctx.Err() != nil || o == nil || o.self != o || o.scope == nil || o.execution == nil || o.execution.resource == nil {
		return nil, nil, ErrNFQWSScopedOwner
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, nil, ErrNFQWSScopedOwner
	}
	if forward {
		if err := o.execution.material.control.Current(ctx); err != nil {
			return nil, nil, err
		}
	} else if err := o.execution.material.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return nil, nil, err
	}
	op := &nfqwsRetainedOperation{owner: o, cleanup: cleanup, forward: forward}
	op.self = op
	op.open.Store(true)
	ctx = context.WithValue(ctx, nfqwsRetainedOperationKey{}, op)
	ctx = context.WithValue(ctx, nfqws2ActiveExecutionKey{}, o.execution)
	ctx = WithReviewGuard(ctx, o.scope.guard)
	ctx = o.scope.contextWith(networkPolicyConsumerContext(ctx, o.scope.plan))
	return ctx, func() { op.open.Store(false) }, nil
}

// CheckRetainedManagedNFQWS uses a fresh actual SAME-App operation; the
// original Apply context and decoded journal cannot supply its authority.
func (m *Manager) CheckRetainedManagedNFQWS(ctx context.Context) error {
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	o := m.retainedNFQOwner()
	if o == nil {
		return ErrNFQWSScopedOwner
	}
	c, closeOperation, err := o.operation(ctx, nil, true)
	if err != nil {
		return err
	}
	defer closeOperation()
	if err := m.checkExecutionRecovery(); err != nil {
		return err
	}
	return o.execution.health(c)
}

// StopRetainedManagedNFQWS joins the original native owner, removes ONLY
// its original COMMON effects, then retires LAN. App retains all source and
// physical/tool owners and the fresh cleanup operation through this return.
func (m *Manager) StopRetainedManagedNFQWS(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	o := m.retainedNFQOwner()
	if o == nil {
		return ErrNFQWSScopedOwner
	}
	c, closeOperation, err := o.operation(ctx, cleanup, false)
	if err != nil {
		return err
	}
	defer closeOperation()
	if err := o.recordsCurrent(); err != nil {
		return err
	}
	if err := o.execution.rollback(c); err != nil {
		return err
	}
	if settled, err := o.execution.verifyRollback(c); err != nil || !settled {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	gate, ok := m.adapter(NetworkPolicyAdapterID)
	if !ok || gate != o.execution.gate {
		return ErrNetworkPolicyConsumers
	}
	if err := o.execution.gate.Deactivate(c); err != nil {
		return err
	}
	if err := o.scope.close(); err != nil {
		return err
	}
	m.retainedNFQMu.Lock()
	if m.retainedNFQ != o {
		m.retainedNFQMu.Unlock()
		return ErrNFQWSScopedOwner
	}
	m.retainedNFQ = nil
	m.retainedNFQMu.Unlock()
	o.closeRecords()
	return nil
}
