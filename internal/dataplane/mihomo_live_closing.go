package dataplane

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Issued only after joined native retirement and all required publications.
// Closing a descriptor invalidates ordinary Current, so this original cursor
// retains custody across close boundaries without reopening an old pathname.
type mihomoLiveClosing struct {
	self        *mihomoLiveClosing
	owner       *mihomoLiveResource
	terminal    *MihomoLiveTerminal
	pending     bool
	index       int
	failure     error
	finished    bool
	beforeClose func(int) error // Private pre-effect fault; an actual Close error is sticky.
}

func (r *mihomoLiveResource) newClosing(t *MihomoLiveTerminal, pending bool) (*mihomoLiveClosing, error) {
	if r == nil || r.self != r || r.scope == nil || r.adapter == nil || r.scope.manager.originalMihomoLive() != r {
		return nil, errMihomoLiveMaterial
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing != nil || r.closed || pending == (t != nil) || t != nil && (t.owner != r || r.terminal != t || !r.retired) {
		return nil, errMihomoLiveMaterial
	}
	s := r.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open || !s.retained || s.pending != pending || s.mihomoLive != r || validateExecutionResources(*s.execution, true) != nil {
		return nil, ErrExecutionJournal
	}
	for _, row := range s.execution.Resources {
		if row.State != "removed" && row.State != "unused" {
			return nil, ErrExecutionJournal
		}
	}
	c := &mihomoLiveClosing{owner: r, terminal: t, pending: pending}
	c.self = c
	r.closing, r.closed = c, true // Revoke every forward borrower before the first close.
	s.mihomoClosing = true
	return c, nil
}

// The Manager serializes all calls. Until the last original control Close,
// each retry requires the caller's fresh same-gate exclusive cleanup review.
func (c *mihomoLiveClosing) finish(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if c == nil || c.self != c || c.owner == nil || c.owner.self != c.owner || c.owner.closing != c || c.owner.scope == nil {
		return errMihomoLiveMaterial
	}
	if c.failure != nil {
		return c.failure
	}
	if c.finished {
		return nil
	}
	r, s := c.owner, c.owner.scope
	if s.manager.originalMihomoLive() != r || cleanup == nil || xraySelectedTCPFinite(ctx) != nil {
		return errMihomoLiveMaterial
	}
	if err := r.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return err
	}
	steps := []func() error{
		func() error {
			if c.terminal != nil {
				return c.terminal.stopped.close()
			}
			return nil
		},
		r.closeNativeLeases,
		s.close,
		r.source.Close,
		func() error {
			if r.child == nil && r.childControl != nil {
				return r.childControl.Close()
			}
			return nil
		},
		r.control.Close,
	}
	for c.index < len(steps) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if c.beforeClose != nil {
			if err := c.beforeClose(c.index); err != nil {
				return err
			}
		}
		if err := steps[c.index](); err != nil {
			c.failure = errors.Join(ErrPolicyAdditionUnknown, err)
			return c.failure // Never retry an ambiguous actual descriptor close.
		}
		c.index++
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r.adapter.mu.Lock()
	defer r.adapter.mu.Unlock()
	if c.pending && (r.adapter.livePending != r || r.adapter.liveActive != nil) || !c.pending && r.adapter.liveActive != r {
		c.failure = ErrPolicyAdditionUnknown
		return c.failure
	}
	if r.adapter.livePending == r {
		r.adapter.livePending = nil
	}
	if r.adapter.liveActive == r {
		r.adapter.liveActive = nil
	}
	s.retained, s.pending = false, false
	s.mihomoRetryRollback = nil
	c.finished = true
	if c.terminal != nil {
		c.terminal.closed = true
	}
	return nil
}
