package dataplane

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// The original exceptional action retains this capsule with its live FD
// custody. Matching serialized intent cannot reconstruct a cleanup owner.
type DomainTCPCleanupFailure struct {
	self   *DomainTCPCleanupFailure
	cursor *domainTCPGlobalSuccessor
	cause  error
}

func (f *DomainTCPCleanupFailure) Error() string {
	if f == nil || f.cause == nil {
		return "original domain action requires cleanup"
	}
	return f.cause.Error()
}
func (f *DomainTCPCleanupFailure) Unwrap() error {
	if f == nil {
		return nil
	}
	return f.cause
}

func domainTCPFailureWithCustody(s *executionResourceScope, cause error) error {
	if s == nil || s.domainSuccessor == nil || !s.domainSuccessor.failedCustody.Load() {
		return cause
	}
	f := &DomainTCPCleanupFailure{cursor: s.domainSuccessor, cause: cause}
	f.self = f
	return f
}

type domainTCPFailureCleanupKey struct{}

// One fresh cleanup operation only. The original forward context stays
// canceled; neither this cursor nor its context can issue Start or a flow.
type domainTCPFailureCleanup struct {
	self            *domainTCPFailureCleanup
	cursor          *domainTCPGlobalSuccessor
	resource        *XrayDomainTCPExecutionResource
	control         *operationgate.ControlEpochReview
	cleanup         *operationgate.ExclusiveCleanupReview
	ctx             context.Context
	active          atomic.Bool
	image           []byte // Exact first authored cleanup phase, retained across a lost ACK.
	imageStage      string
	imageACK        bool
	capture         *domainTCPCaptureExecutionResource
	captureDetached bool
	standby         *domainTCPStandbyOwner
	retained        *retainedXrayExecution
	standbyImage    []byte
	restored        bool // Protected by Manager.operation; no forward authority.
	fault           func(string) error
}

func (r *domainTCPFailureCleanup) local(ctx context.Context, p *XrayDomainTCPExecutionResource) error {
	if r == nil || r.self != r || !r.active.Load() || ctx == nil || ctx.Err() != nil || ctx.Value(domainTCPFailureCleanupKey{}) != r || p == nil || p.self != p || r.resource != p || p.scope == nil || p.scope.domainSuccessor != r.cursor || r.cursor == nil || r.cursor.cleanup != r || !r.cursor.failedCustody.Load() || p.material == nil || p.material.self != p.material || p.material.resource != p || p.material.control != r.control || r.cleanup == nil || r.control == nil || r.ctx == nil || r.ctx.Err() != nil || xraySelectedTCPFinite(ctx) != nil {
		return ErrPolicyAdditionUnknown
	}
	deadline, finite := ctx.Deadline()
	bound, bounded := r.ctx.Deadline()
	if !finite || !bounded || deadline.After(bound) {
		return ErrPolicyAdditionUnknown
	}
	return nil
}

func (p *XrayDomainTCPExecutionResource) failureCleanup(ctx context.Context) (*domainTCPFailureCleanup, error) {
	if ctx == nil {
		return nil, ErrPolicyAdditionUnknown
	}
	raw := ctx.Value(domainTCPFailureCleanupKey{})
	if raw == nil {
		return nil, nil
	}
	r, _ := raw.(*domainTCPFailureCleanup)
	if r == nil {
		return nil, ErrPolicyAdditionUnknown
	}
	return r, r.local(ctx, p)
}

func (p *XrayDomainTCPExecutionResource) cleanupReview(ctx context.Context) (*operationgate.ExclusiveCleanupReview, error) {
	r, err := p.failureCleanup(ctx)
	if err != nil {
		return nil, err
	}
	if r != nil {
		return r.cleanup, nil
	}
	if p == nil || p.material == nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	return p.material.cleanup, nil
}

// This exact typed cursor is the sole domain exception to a sticky forward
// publication error. It preserves every remaining original-owner comparison.
// Called under scope.mu; it performs no callbacks or control/source reentry.
func domainTCPFailureCleanupOwner(ctx context.Context, s *executionResourceScope) bool {
	if ctx == nil || s == nil || s.domainSuccessor == nil {
		return false
	}
	r, _ := ctx.Value(domainTCPFailureCleanupKey{}).(*domainTCPFailureCleanup)
	return r != nil && r.cursor == s.domainSuccessor && r.resource != nil && r.resource.scope == s && r.local(ctx, r.resource) == nil
}

// JoinFailedDomainTCPNative joins the original child and its source/handlers.
// Successful return acknowledges the child row and closed original source,
// not capture-rule retirement, pool readiness or release of FD custody.
func (m *Manager) JoinFailedDomainTCPNative(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview, history *updatecheck.ExecutionHistoryAdmission, failure *DomainTCPCleanupFailure) error {
	return m.cleanupFailedDomainTCP(ctx, cleanup, history, failure, false, nil)
}

func (m *Manager) cleanupFailedDomainTCP(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview, history *updatecheck.ExecutionHistoryAdmission, failure *DomainTCPCleanupFailure, restore bool, result *domainTCPFailureRestoredHandles) error {
	if m == nil || ctx == nil || cleanup == nil || history == nil || failure == nil || failure.self != failure || failure.cursor == nil || failure.cursor.scope == nil || failure.cursor.scope.manager != m || xraySelectedTCPFinite(ctx) != nil || restore && result == nil {
		return ErrPolicyAdditionUnknown
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrPolicyAdditionUnknown
	}
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	if err := history.CheckWrite(ctx, 8); err != nil {
		return err
	} // Outside all leaf locks.
	c := failure.cursor
	if err := c.original(); err != nil {
		return err
	}
	if restore && c.cleanup != nil && c.cleanup.restored {
		r := c.cleanup
		if r.self != r || r.standby == nil || r.standby.process == nil || r.standby.process.material.control != r.control {
			return ErrPolicyAdditionUnknown
		}
		if err := r.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
			return err
		}
		o := r.standby.original
		o.mu.Lock()
		retirement := o.standbyRetirement
		validRetirement := retirement == nil || retirement.self == retirement && retirement.owner == r.standby
		removed := retirement != nil && retirement.finished
		o.mu.Unlock()
		if !validRetirement {
			return ErrPolicyAdditionUnknown
		}
		if removed {
			if err := m.CheckExecutionRecovery(ctx); err != nil {
				return err
			}
		} else if retirement == nil {
			if err := o.RetainedStandbyCurrent(ctx); err != nil {
				return err
			}
		}
		// An original unfinished compensation intentionally has pending=true.
		// Do not require a known-standby read before its SAME existing retry:
		// RetireUnpublished rechecks removed receipt/kernel/original partial
		// writers under a separate fresh operation and refuses unknown cleanup.
		return r.copyRestoredHandles(result)
	}
	s := c.scope
	s.mu.Lock()
	var p *XrayDomainTCPExecutionResource
	valid := s.open && s.pending && !s.observationOpen.Load() && s.ctx.Err() != nil && c.failedCustody.Load() && len(s.xrayDomainTCP) == 1
	for _, original := range s.xrayDomainTCP {
		p = original
	}
	s.mu.Unlock()
	if !valid || p == nil || p.self != p || p.scope != s || p.material == nil || p.material.self != p.material || p.material.resource != p || p.material.control == nil {
		return ErrPolicyAdditionUnknown
	}
	if err := p.material.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return err
	}
	if !p.mu.TryLock() {
		return ErrPolicyAdditionUnknown
	} // No detached lock waiter.
	locked := true
	defer func() {
		if locked {
			p.mu.Unlock()
		}
	}()
	if err := p.failureNativeReturnedLocked(); err != nil {
		return err
	}
	r := c.cleanup
	if r == nil {
		r = &domainTCPFailureCleanup{cursor: c, resource: p, control: p.material.control}
		c.mu.Lock()
		c.cleanupIssued.Store(true)
		r.fault = c.cleanupFault
		c.mu.Unlock()
		r.self = r
		c.cleanup = r
	}
	if r.self != r || r.cursor != c || r.resource != p || r.control != p.material.control {
		return ErrPolicyAdditionUnknown
	}
	r.cleanup = cleanup
	r.ctx = s.contextWith(context.WithValue(ctx, domainTCPFailureCleanupKey{}, r))
	if !r.active.CompareAndSwap(false, true) {
		return ErrPolicyAdditionUnknown
	}
	defer r.active.Store(false)
	if err := r.local(r.ctx, p); err != nil {
		return err
	}
	// Scope.close already canceled and joined actual Start. The actual native
	// return channel above also joins consume/handlers/finalizer; resource.mu
	// alone cannot do that because it is released during the callback.
	if err := p.stopOriginalNative(r.ctx); err != nil {
		return err
	}
	p.mu.Unlock()
	locked = false
	// DNS callbacks can themselves need resource.mu. Never hold that mutex
	// while Close joins their actual publication barrier and socket session.
	if _, err := r.closeOriginalDNS(r.ctx); err != nil {
		return err
	}
	if restore {
		if err := r.restoreOriginalStandby(r.ctx, history, failure.cause); err != nil {
			return err
		}
		return r.copyRestoredHandles(result)
	}
	return errors.Join(c.records.current(r.ctx, true), c.comparePrior(r.ctx, true), r.control.CurrentForCleanupOperation(r.ctx, cleanup))
}

// Caller holds resource.mu. A missing channel is not evidence that an issued
// Start/handler never happened; only the genuine producer closes this channel.
func (p *XrayDomainTCPExecutionResource) failureNativeReturnedLocked() error {
	if p == nil || p.self != p || p.nativeDone == nil {
		return ErrPolicyAdditionUnknown
	}
	select {
	case <-p.nativeDone:
		return nil
	default:
		return ErrPolicyAdditionUnknown
	}
}
