package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Memory-only custody of one finite retained check. The serialized state
// cannot mint this writer, its cleanup review or either original journal FD.
// All fields are protected by owner.scope.mu.
type mihomoLiveHealthCheck struct {
	self                               *mihomoLiveHealthCheck
	owner                              *mihomoLiveResource
	cleanup                            *operationgate.ExclusiveCleanupReview
	before                             []byte
	header                             ExecutionMihomoLiveHealthOperation
	open, failed, publishing, stopping bool
	fault                              func(string) error // Refusal-only private model cuts; never an admission.
}

func (r *mihomoLiveResource) beginHealthCheck(ctx context.Context) (*mihomoLiveHealthCheck, error) {
	if r == nil || r.self != r || r.scope == nil || r.records == nil || r.historyAdmission == nil || r.control == nil {
		return nil, errMihomoLiveMaterial
	}
	// A failed reader9 check never authorizes this writer. No new state is
	// published before every retained controller has actually admitted it.
	if err := r.historyAdmission.CheckWrite(ctx, 9); err != nil {
		return nil, err
	}
	cleanup, err := r.control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return nil, err
	}
	s := r.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.retained || s.pending || s.failure != nil || r.healthCheck != nil || s.execution.State != "committed" || validateExecutionResources(*s.execution, true) != nil {
		return nil, ErrExecutionJournal
	}
	if err := r.localRecord(ctx, true); err != nil {
		return nil, err
	}
	if err := r.records.current(ctx, true); err != nil {
		return nil, err
	}
	before, err := json.Marshal(s.execution)
	if err != nil {
		return nil, err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	h := ExecutionMihomoLiveHealthOperation{Schema: 1, ID: hex.EncodeToString(nonce[:]), PlanID: s.execution.PlanID, PlanDigest: s.execution.Digest, BeforeSHA256: nodeDefaultSourceMaterialHash(before), Phase: "checking"}
	c := &mihomoLiveHealthCheck{owner: r, cleanup: cleanup, open: true, before: before, header: h}
	c.self = c
	r.healthCheck = c // Before the first possible partial two-writer ACK.
	s.execution.State, s.execution.FinishedAt = mihomoActiveCheckingState, ""
	s.execution.MihomoLiveHealthOperation = &h
	return c, c.publishLocked()
}

// Caller holds scope.mu. A publication failure retains this exact cursor and
// both accepted writer images, rather than erasing the cleanup owner.
func (c *mihomoLiveHealthCheck) publishLocked() error {
	if c == nil || c.self != c || c.owner == nil || c.owner.healthCheck != c || !c.open && !c.stopping {
		return ErrExecutionJournal
	}
	s := c.owner.scope
	h := s.execution.MihomoLiveHealthOperation
	if h == nil || h.Schema != c.header.Schema || h.ID != c.header.ID || h.PlanID != c.header.PlanID || h.PlanDigest != c.header.PlanDigest || h.BeforeSHA256 != c.header.BeforeSHA256 {
		return ErrExecutionJournal
	}
	c.publishing = true
	defer func() { c.publishing = false }()
	return s.manager.writeExecutionOwned(s.root, *s.execution, s)
}

func (c *mihomoLiveHealthCheck) fail() {
	if c == nil || c.self != c || c.owner == nil {
		return
	}
	s := c.owner.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.owner.healthCheck == c {
		c.open, c.failed, s.pending = false, true, true
		s.execution.State, s.execution.FinishedAt = mihomoActiveCheckingState, ""
		h := c.header
		s.execution.MihomoLiveHealthOperation = &h
	}
}

func (r *mihomoLiveResource) prepareLiveStop(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	s := r.scope
	if err := r.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return err
	}
	s.mu.Lock()
	hasHeader := s.execution.MihomoLiveHealthOperation != nil
	s.mu.Unlock()
	if hasHeader {
		if r.historyAdmission == nil {
			return ErrExecutionJournal
		}
		if err := r.historyAdmission.CheckWrite(ctx, 9); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := r.healthCheck
	if s.failure != nil {
		return errors.Join(ErrExecutionJournal, s.failure)
	}
	if err := r.localRecord(ctx, false); err != nil {
		return err
	}
	if err := r.records.current(ctx, false); err != nil {
		return err
	}
	if !hasHeader {
		if s.pending || s.execution.State != "committed" && s.execution.State != "rolling-back" {
			return ErrExecutionJournal
		}
		s.execution.State, s.execution.FinishedAt = "rolling-back", ""
		return s.persist()
	}
	if c == nil {
		if s.pending || s.execution.State != "committed" || s.execution.MihomoLiveHealthOperation.Phase != "settled" {
			return ErrExecutionJournal
		}
		before, err := json.Marshal(s.execution)
		if err != nil {
			return err
		}
		c = &mihomoLiveHealthCheck{owner: r, cleanup: cleanup, before: before, header: *s.execution.MihomoLiveHealthOperation, failed: true}
		c.self = c
		r.healthCheck = c
	}
	if c.self != c || c.owner != r || !c.failed || c.open {
		return ErrExecutionJournal
	}
	c.stopping = true
	s.pending = true
	s.execution.State, s.execution.FinishedAt = "rolling-back", ""
	h := c.header
	h.Phase = "retiring"
	s.execution.MihomoLiveHealthOperation = &h
	return c.publishLocked()
}

func (r *mihomoLiveResource) finishHealthStop(ctx context.Context) error {
	s := r.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	c := r.healthCheck
	if c == nil {
		if s.execution.MihomoLiveHealthOperation != nil {
			return ErrExecutionJournal
		}
		s.execution.State, s.execution.FinishedAt = "rolled-back", time.Now().UTC().Format(time.RFC3339Nano)
		return s.persist()
	}
	if c.self != c || c.owner != r || !c.failed || !c.stopping || !s.pending {
		return ErrExecutionJournal
	}
	for _, row := range s.execution.Resources {
		if row.ID == r.id {
			if row.State != "removed" {
				return ErrExecutionJournal
			}
		} else if !mihomoTransitJoinedRow(s.issued[row.ID], row) {
			return ErrExecutionJournal
		}
	}
	if len(s.issued) != len(s.execution.Resources)-1 {
		return ErrExecutionJournal
	}
	s.execution.State, s.execution.FinishedAt = "rolled-back", time.Now().UTC().Format(time.RFC3339Nano)
	h := c.header
	h.Phase = "retired"
	s.execution.MihomoLiveHealthOperation = &h
	if err := c.publishLocked(); err != nil {
		return err
	}
	if c.fault != nil {
		if err := c.fault("before-retirement-current"); err != nil {
			return err
		}
	}
	if err := r.records.current(ctx, true); err != nil {
		return err
	}
	s.pending, c.stopping, r.healthCheck = false, false, nil
	return nil
}

// Uses only actual leases retained by this original check, before their TUN
// and native owners are joined. A serialized removed row is never sufficient.
func (r *mihomoLiveResource) cleanupHealthTransits(ctx context.Context) error {
	s := r.scope
	s.mu.Lock()
	var resources []*executionTransitResource
	for _, resource := range s.issued {
		if resource.probe != nil && !resource.finished {
			resources = append(resources, resource)
		}
	}
	s.mu.Unlock()
	var result error
	for _, resource := range resources {
		b := resource.probe
		if b.self != b || b.lease == nil || b.spec != resource.spec || b.root != resource.root || b.lease.digest != resource.digest {
			result = errors.Join(result, ErrNodeTransitUnavailable)
			continue
		}
		// Preserve the original pre-effect refusal solely for its one-shot
		// unused proof. Other body errors do not prevent real removal/settlement.
		var body error
		if isNodeTransitBeforeEffects(b.resultErr) {
			body = b.resultErr
		}
		err := finishRegisteredNodeRouterProbe(context.WithValue(ctx, nodeTransitCleanupKey{}, true), b.spec, b.registration, b.lease, b, body)
		if resource.finished {
			err = nil
		} // Body refusal remains negative; cleanup ACK is independent.
		result = errors.Join(result, err)
	}
	return result
}

func (c *mihomoLiveHealthCheck) complete(ctx context.Context) error {
	if c == nil || c.self != c || c.owner == nil || ctx == nil {
		return ErrExecutionJournal
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrExecutionJournal, err)
	}
	r, s := c.owner, c.owner.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.healthCheck != c || !c.open || c.failed || s.pending || s.failure != nil || s.execution.State != mihomoActiveCheckingState {
		return ErrExecutionJournal
	}
	if err := r.localRecord(ctx, true); err != nil {
		return err
	}
	for _, row := range s.execution.Resources {
		if row.ID != r.id && (row.Kind != "node-transit" || !mihomoTransitJoinedRow(s.issued[row.ID], row)) {
			return ErrExecutionJournal
		}
	}
	if len(s.issued) != len(s.execution.Resources)-1 {
		return ErrExecutionJournal
	}
	if err := r.records.current(ctx, true); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.execution.State, s.execution.FinishedAt = "committed", time.Now().UTC().Format(time.RFC3339Nano)
	h := c.header
	h.Phase = "settled"
	s.execution.MihomoLiveHealthOperation = &h
	if err := c.publishLocked(); err != nil {
		return err
	}
	if c.fault != nil {
		if err := c.fault("before-completion-current"); err != nil {
			return err
		}
	}
	if err := r.records.current(ctx, true); err != nil {
		return err
	}
	c.open, r.healthCheck = false, nil
	return nil
}

// This nested borrower never changes the outer forward marker: context values
// are immutable and each operation revokes only its own private token.
func (r *mihomoLiveResource) healthCleanupOperation(ctx context.Context) (context.Context, func(), error) {
	if r == nil || r.self != r || ctx == nil {
		return nil, nil, errMihomoLiveMaterial
	}
	outer, _ := ctx.Value(mihomoLiveOperationKey{}).(*mihomoLiveOperation)
	if outer == nil || outer.self != outer || outer.owner != r || !outer.forward || !outer.open.Load() {
		return nil, nil, errMihomoLiveMaterial
	}
	s := r.scope
	s.mu.Lock()
	c := r.healthCheck
	valid := c != nil && c.self == c && c.owner == r && c.open && !c.failed && c.cleanup != nil
	s.mu.Unlock()
	if !valid {
		return nil, nil, errMihomoLiveMaterial
	}
	return r.operation(ctx, c.cleanup, false)
}
