package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type mihomoLiveOperationKey struct{}
type mihomoLiveOperation struct {
	self    *mihomoLiveOperation
	owner   *mihomoLiveResource
	cleanup *operationgate.ExclusiveCleanupReview
	forward bool
	open    atomic.Bool
}

// A fresh actual operation can borrow only this original retained owner. The
// old Apply context is never extended or held to keep the child alive.
func (r *mihomoLiveResource) operation(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview, forward bool) (context.Context, func(), error) {
	if r == nil || r.self != r || r.scope == nil || r.scope.mihomoLive != r || r.control == nil || xraySelectedTCPFinite(ctx) != nil {
		return nil, nil, errMihomoLiveMaterial
	}
	r.scope.mu.Lock()
	valid := r.scope.open && r.scope.retained && (!forward || !r.scope.pending)
	r.scope.mu.Unlock()
	r.mu.Lock()
	valid = valid && (!forward || !r.retired) && !r.closed
	r.mu.Unlock()
	if !valid {
		return nil, nil, errMihomoLiveMaterial
	}
	if forward {
		if err := r.control.Current(ctx); err != nil {
			return nil, nil, err
		}
	} else if err := r.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return nil, nil, err
	}
	o := &mihomoLiveOperation{owner: r, cleanup: cleanup, forward: forward}
	o.self = o
	o.open.Store(true)
	ctx = context.WithValue(ctx, mihomoLiveOperationKey{}, o)
	ctx = r.scope.contextWith(networkPolicyConsumerContext(ctx, r.scope.plan))
	return ctx, func() { o.open.Store(false) }, nil
}

// Caller holds scope.mu. Checking a copied marker, an old closed borrower or
// another original resource never grants access to this scope's journal.
func (s *executionResourceScope) checkRetainedMihomoOperation(ctx context.Context, forward bool) error {
	if s == nil || !s.retained || s.mihomoLive == nil || xraySelectedTCPFinite(ctx) != nil {
		return errMihomoLiveMaterial
	}
	o, _ := ctx.Value(mihomoLiveOperationKey{}).(*mihomoLiveOperation)
	if o == nil || o.self != o || !o.open.Load() || o.owner != s.mihomoLive || o.forward != forward || forward && s.pending || !forward && o.cleanup == nil {
		return errMihomoLiveMaterial
	}
	return nil
}

func (m *Manager) originalMihomoLive() *mihomoLiveResource {
	adapter, found := m.adapter("mihomo")
	a, ok := adapter.(*MihomoProbeAdapter)
	if !found || !ok || a == nil || a.self != a {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.livePending != nil {
		return a.livePending
	}
	return a.liveActive
}

func (m *Manager) checkRetainedMihomoRecord(record Execution) error {
	active := false
	for _, row := range record.Resources {
		active = active || row.MihomoLive != nil && row.State == "active"
	}
	if !active {
		return nil
	}
	r := m.originalMihomoLive()
	if r == nil || r.self != r || r.scope == nil || r.records == nil || r.scope.manager != m {
		return errMihomoLiveMaterial
	}
	s := r.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	expected, expectedErr := json.Marshal(s.execution)
	actual, actualErr := json.Marshal(record)
	if !s.open || !s.retained || s.pending || s.mihomoLive != r || expectedErr != nil || actualErr != nil || !bytes.Equal(expected, actual) {
		return errMihomoLiveMaterial
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	return r.records.current(ctx, true)
}

// Unknown original work keeps the same scope and descriptors available solely
// for a fresh cleanup operation. It never publishes an ACTIVE acknowledgement.
func (m *Manager) retainOriginalMihomo(s *executionResourceScope, pending bool) error {
	if s == nil || s.manager != m || s.mihomoLive == nil || s.mihomoLive.self != s.mihomoLive || s.mihomoLive.scope != s {
		return errMihomoLiveMaterial
	}
	r := s.mihomoLive
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open || s.retained || !pending && (s.execution.State != "committed" || validateExecutionResources(*s.execution, true) != nil) {
		return ErrExecutionJournal
	}
	var detached *Execution
	if !pending {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		if err := r.records.current(ctx, true); err != nil {
			return err
		}
		copy := *s.execution
		copy.Resources = cloneExecutionResources(s.execution.Resources)
		copy.Steps = append([]ExecutionStep(nil), s.execution.Steps...)
		detached = &copy
	}
	r.adapter.mu.Lock()
	defer r.adapter.mu.Unlock()
	if r.adapter.livePending != r || !pending && r.adapter.liveActive != nil && r.adapter.liveActive != r {
		return errMihomoLiveMaterial
	}
	if detached != nil {
		s.execution = detached
	}
	s.retained, s.pending = true, pending
	s.observationOpen.Store(false)
	s.cancel() // Only old Apply borrowers; component children have their own lifetime.
	if !pending {
		r.adapter.livePending = nil
		r.adapter.liveActive = r
	}
	return nil
}

// Metadata transitions are subordinate to the live controller's actual
// observations. This helper never performs or claims native cleanup itself.
func (r *mihomoLiveResource) recordPhase(ctx context.Context, phase string, observation *MihomoLiveRuntimeObservation) error {
	if r == nil || r.self != r || r.scope == nil || xraySelectedTCPFinite(ctx) != nil {
		return errMihomoLiveMaterial
	}
	s := r.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	forward := phase != "removed" && phase != "unused" && phase != "closed"
	if err := r.localRecord(ctx, forward); err != nil {
		return err
	}
	index, err := r.recordIndex()
	if err != nil {
		return err
	}
	if observation != nil {
		if r.definition.Observation != nil && *r.definition.Observation != *observation {
			return ErrExecutionJournal
		}
		copy := *observation
		r.definition.Observation = &copy
	}
	row := &s.execution.Resources[index]
	row.Phase = phase
	row.State = "prepared"
	if phase == "removed" || phase == "unused" || phase == "active" {
		row.State = phase
	}
	d := r.definition.Clone()
	row.MihomoLive = &d
	if err := validateMihomoLiveExecutionResource(*s.execution, *row, false); err != nil {
		s.failure = errors.Join(s.failure, err)
		return err
	}
	return s.persist()
}

// The original writer can acknowledge ACTIVE only after the last real TUN
// service check and all temporary transit owners have settled.
func (s *executionResourceScope) prepareActiveMihomo(ctx context.Context) error {
	if s == nil || s.mihomoLive == nil || s.mihomoLive.scope != s || s.retained {
		return errMihomoLiveMaterial
	}
	r := s.mihomoLive
	ctx = s.contextWith(networkPolicyConsumerContext(ctx, s.plan))
	if err := r.currentLive(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	valid := s.execution.State == "committing"
	for _, row := range s.execution.Resources {
		if row.ID != r.id {
			valid = valid && (row.State == "removed" || row.State == "unused")
		}
	}
	s.mu.Unlock()
	if !valid {
		return ErrExecutionJournal
	}
	return r.recordPhase(ctx, "active", nil)
}

// These snapshots expose custody, not runtime health or cleanup evidence.
func (m *Manager) HasPendingMihomoLive() bool {
	if m == nil {
		return false
	}
	if m.mihomoPreparationPending() {
		return true
	}
	r := m.originalMihomoLive()
	if r == nil || r.scope == nil {
		return false
	}
	r.mu.Lock()
	closing := r.closing != nil
	r.mu.Unlock()
	if closing {
		return true
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	return r.scope.open && r.scope.retained && r.scope.pending
}

func (m *Manager) mihomoPreparationPending() bool {
	registered, ok := m.adapter("mihomo")
	a, typed := registered.(*MihomoProbeAdapter)
	if !ok || !typed || a == nil || a.self != a {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.livePreparing != nil
}

func (m *Manager) CheckMihomoLive(ctx context.Context) error {
	if m == nil {
		return errMihomoLiveMaterial
	}
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	r := m.originalMihomoLive()
	if r == nil {
		return errMihomoLiveMaterial
	}
	c, end, err := r.operation(ctx, nil, true)
	if err != nil {
		return err
	}
	defer end()
	return r.currentLive(c)
}

// A retry continues the SAME original Manager compensation closure. It never
// replays a serialized plan, creates a new source, or starts replacement work.
func (m *Manager) JoinPendingMihomoLive(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if m == nil || cleanup == nil {
		return errMihomoLiveMaterial
	}
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	r := m.originalMihomoLive()
	if r == nil || r.scope == nil {
		return errMihomoLiveMaterial
	}
	if r.closing != nil {
		return r.closing.finish(ctx, cleanup)
	}
	s := r.scope
	s.mu.Lock()
	retry, pending := s.mihomoRetryRollback, s.pending
	s.mu.Unlock()
	if !pending || retry == nil {
		return errMihomoLiveMaterial
	}
	c, end, err := r.operation(ctx, cleanup, false)
	if err != nil {
		return err
	}
	defer end()
	if err := retry(c); err != nil {
		return err
	}
	if err := r.observeLiveInactive(c, cleanup); err != nil {
		return err
	}
	if err := r.records.current(c, true); err != nil {
		return err
	}
	if err := m.checkExecutionRecovery(); err != nil {
		return err
	}
	s.mu.Lock()
	valid := s.execution.State == "rolled-back" && validateExecutionResources(*s.execution, true) == nil
	for _, row := range s.execution.Resources {
		valid = valid && (row.State == "removed" || row.State == "unused")
	}
	if valid {
		// Only complete genuine compensation, fresh absence, two newly authored
		// durable records and the existing recovery reader may settle the earlier
		// publication failure. No forward borrower survives this transition.
		s.failure = nil
	}
	s.mu.Unlock()
	if !valid {
		return ErrExecutionJournal
	}
	closing, err := r.newClosing(nil, true)
	if err != nil {
		return err
	}
	return closing.finish(ctx, cleanup)
}
