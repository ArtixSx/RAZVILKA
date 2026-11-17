package dataplane

import (
	"context"
	"errors"
	"sync"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Only joined original runtime retirement can issue this terminal. Persisted
// definitions, a new adapter and a cold PID receipt cannot reconstruct it.
type MihomoLiveTerminal struct {
	self     *MihomoLiveTerminal
	mu       sync.Mutex
	owner    *mihomoLiveResource
	stopped  *mihomoStoppedPlanPublication
	closed   bool
	closeErr error
}

// StopMihomoLive runs before any new Apply journal. It keeps the original two
// authored records and source owners available across partial Stop failures.
func (m *Manager) StopMihomoLive(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) (*MihomoLiveTerminal, error) {
	if m == nil || cleanup == nil {
		return nil, errMihomoLiveMaterial
	}
	if err := m.beginOperation(ctx); err != nil {
		return nil, err
	}
	defer m.endOperation()
	r := m.originalMihomoLive()
	if r == nil || r.self != r || r.scope == nil {
		return nil, errMihomoLiveMaterial
	}
	if err := r.resumeTransitArchive(ctx, cleanup); err != nil {
		return nil, err
	}
	r.scope.mu.Lock()
	pending := r.scope.pending
	healthPending := r.healthCheck != nil && r.healthCheck.self == r.healthCheck && r.healthCheck.owner == r && r.healthCheck.failed
	r.scope.mu.Unlock()
	if pending && !healthPending {
		return nil, ErrPolicyAdditionUnknown
	}
	c, end, err := r.operation(ctx, cleanup, false)
	if err != nil {
		return nil, err
	}
	defer end()
	prepareErr := mihomoLiveStopAt("prepare", r.prepareLiveStop(c, cleanup))
	// Unknown journal ownership must be repaired by its original writer before
	// a Stop result may advertise durable completion. Native cleanup itself is
	// allowed by the adapter's same-owner recovery lane on partial publication.
	journalErr := mihomoLiveStopAt("record-pair", r.records.current(c, true))
	cleanupErr := r.cleanupLive(c, cleanup)
	if err := errors.Join(prepareErr, journalErr, cleanupErr); err != nil {
		return nil, err
	}
	if err := r.finishHealthStop(c); err != nil {
		return nil, mihomoLiveStopAt("settled-header", err)
	}
	if err := r.observeLiveInactive(c, cleanup); err != nil {
		return nil, mihomoLiveStopAt("inactive-recheck", err)
	}
	r.scope.mu.Lock()
	terminal := validateExecutionResources(*r.scope.execution, true) == nil
	for _, row := range r.scope.execution.Resources {
		terminal = terminal && (row.State == "removed" || row.State == "unused")
	}
	r.scope.mu.Unlock()
	if !terminal {
		return nil, mihomoLiveStopAt("terminal-rows", ErrExecutionJournal)
	}
	if err := r.records.current(c, true); err != nil {
		return nil, mihomoLiveStopAt("final-record-pair", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.retired = true
	if r.terminal == nil {
		r.terminal = &MihomoLiveTerminal{owner: r}
		r.terminal.self = r.terminal
	}
	return r.terminal, nil
}

func (t *MihomoLiveTerminal) current(ctx context.Context) error {
	if t == nil || t.self != t || t.closed || t.owner == nil || t.owner.self != t.owner || t.owner.scope == nil || xraySelectedTCPFinite(ctx) != nil {
		return errMihomoLiveMaterial
	}
	r := t.owner
	r.mu.Lock()
	valid := r.retired && r.terminal == t
	r.mu.Unlock()
	s := r.scope
	if !valid || s.manager.originalMihomoLive() != r {
		return errMihomoLiveMaterial
	}
	s.mu.Lock()
	valid = s.open && s.retained && s.mihomoLive == r && validateExecutionResources(*s.execution, true) == nil
	for _, row := range s.execution.Resources {
		valid = valid && (row.State == "removed" || row.State == "unused")
	}
	s.mu.Unlock()
	if !valid {
		return ErrExecutionJournal
	}
	return r.records.current(ctx, true)
}

func (t *MihomoLiveTerminal) ObserveRetired(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if t == nil || t.owner == nil || t.owner.scope == nil {
		return errMihomoLiveMaterial
	}
	m := t.owner.scope.manager
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.current(ctx); err != nil {
		return err
	}
	c, end, err := t.owner.operation(ctx, cleanup, false)
	if err != nil {
		return err
	}
	defer end()
	return errors.Join(t.owner.observeLiveInactive(c, cleanup), t.current(c))
}

// Close relinquishes custody only after both stopped-plan publications have
// their original ACK. A failed native/journal observation keeps this terminal
// available to the SAME App's retry; it never closes an unfinished process.
func (t *MihomoLiveTerminal) Close(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if t == nil || t.self != t || t.owner == nil || t.owner.scope == nil {
		return errMihomoLiveMaterial
	}
	m := t.owner.scope.manager
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return t.closeErr
	}
	r := t.owner
	if r.closing != nil {
		return r.closing.finish(ctx, cleanup)
	}
	if err := t.current(ctx); err != nil {
		return err
	}
	c, end, err := r.operation(ctx, cleanup, false)
	if err != nil {
		return err
	}
	defer end()
	if err := r.observeLiveInactive(c, cleanup); err != nil {
		return err
	}
	if t.stopped == nil || t.stopped.failure != nil || !t.stopped.files[0].ack || !t.stopped.files[1].ack {
		return ErrExecutionJournal
	}
	if err := t.stopped.current(c); err != nil {
		return err
	}
	closing, err := r.newClosing(t, false)
	if err != nil {
		return err
	}
	return closing.finish(ctx, cleanup)
}
