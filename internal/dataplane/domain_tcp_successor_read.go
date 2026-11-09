package dataplane

import (
	"context"
	"errors"
	"reflect"
)

// This is explicit forwarding of an already-open original pre-Add byte view,
// never a new context grant. It lives only inside one counterfactual row read.
// Prior owners retain independent full bytes. Only the exact live successor's
// listener may derive its original process-reader view from this same loan.
type domainTCPSuccessorRead struct {
	self         *domainTCPSuccessorRead
	cursor       *domainTCPGlobalSuccessor
	loan         *domainTCPPreAddLoan
	files        *xrayDomainTCPFileObservation
	owner        *DomainTCPOriginalScope
	baseline     *syntheticBaselineExecutionResource
	capture      *domainTCPCaptureExecutionResource
	process      *XrayDomainTCPExecutionResource
	witness      *domainTCPPoolListenerWitness
	rootCtx, ctx context.Context
	prior        *XrayDomainTCPExecutionResource
}

func (c *domainTCPGlobalSuccessor) originalSuccessorRead(ctx context.Context) (*domainTCPSuccessorRead, error) {
	if ctx == nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	value := ctx.Value(domainTCPPreAddKey{})
	if value == nil {
		return nil, nil
	}
	loan, ok := value.(*domainTCPPreAddLoan)
	if !ok || loan == nil || loan.self != loan || !loan.open.Load() || !reflect.TypeOf(ctx).Comparable() || loan.ctx != ctx || loan.read == nil || loan.read.self != loan.read || loan.read.process == nil || loan.files == nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	process := loan.read.process
	if c == nil || c.scope == nil || process.scope != c.scope || c.scope.domainSuccessor != c || c.original() != nil || loan.files.current(ctx, process) != nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	witness := c.listener.Load()
	read := &domainTCPSuccessorRead{cursor: c, loan: loan, files: loan.files, owner: loan.read.owner, baseline: loan.read.baseline, capture: loan.read.capture, process: process, witness: witness, rootCtx: ctx, ctx: ctx}
	read.self = read
	if err := read.loanCurrent(ctx); err != nil {
		return nil, err
	}
	if witness == nil {
		return nil, nil
	} // Valid original loan, no live successor view yet.
	if err := read.rootCurrent(ctx); err != nil {
		return nil, err
	}
	return read, nil
}

func (r *domainTCPSuccessorRead) rootCurrent(ctx context.Context) error {
	if err := r.loanCurrent(ctx); err != nil {
		return err
	}
	if r.witness == nil || r.witness.self != r.witness || r.cursor.listener.Load() != r.witness || r.witness.cursor != r.cursor || r.witness.resource != r.process {
		return ErrDomainPolicyTCPConsumer
	}
	return nil
}

func (r *domainTCPSuccessorRead) loanCurrent(ctx context.Context) error {
	if ctx == nil {
		return ErrDomainPolicyTCPConsumer
	}
	if r == nil || r.self != r || r.rootCtx == nil || !reflect.TypeOf(ctx).Comparable() || ctx != r.rootCtx || r.loan == nil || r.loan.self != r.loan || !r.loan.open.Load() || r.loan.ctx != r.rootCtx || r.loan.files != r.files || r.files == nil || r.loan.read == nil || r.loan.read.self != r.loan.read || r.loan.read.owner != r.owner || r.loan.read.baseline != r.baseline || r.loan.read.capture != r.capture || r.loan.read.process != r.process || r.cursor == nil || r.cursor.self != r.cursor || r.cursor.pool == nil || r.cursor.scope == nil || r.cursor.scope.manager != r.cursor.pool.manager || r.process == nil || r.process.self != r.process || r.process.scope != r.cursor.scope || r.cursor.scope.domainSuccessor != r.cursor || r.owner == nil || r.owner.self != r.owner || r.baseline == nil || r.baseline.self != r.baseline || r.baseline.capture == nil || r.baseline.capture.owner != r.owner || r.owner.binding != r.baseline.binding || r.process.material == nil || r.process.material.binding != r.baseline.binding {
		return errors.Join(ErrDomainPolicyTCPConsumer, ctx.Err())
	}
	r.owner.mu.Lock()
	same := !r.owner.closed && r.owner.process == r.process && r.owner.capture == r.baseline.capture && r.owner.baseline == r.baseline && (r.capture == nil || r.owner.captureResource == r.capture)
	r.owner.mu.Unlock()
	if !same {
		return ErrDomainPolicyTCPConsumer
	}
	if r.capture != nil && (r.capture.process != r.process || r.capture.mapping != r.baseline.mapping || r.capture.capture != r.baseline.capture || r.capture.backend != r.baseline.backend || r.capture.tools != r.baseline.tools) {
		return ErrDomainPolicyTCPConsumer
	}
	return errors.Join(r.cursor.original(), r.files.current(r.rootCtx, r.process), ctx.Err())
}

// The sole intermediate context transform is the old scope's own contextWith.
// Keep its exact cancellation/value semantics; never lend this view to old.
func (r *domainTCPSuccessorRead) forPriorContext(parent context.Context, old *XrayDomainTCPExecutionResource) (context.Context, *domainTCPSuccessorRead, error) {
	if r == nil || r.self != r || r.prior != nil || r.ctx != parent || r.rootCurrent(parent) != nil || old == nil || old == r.process || old.scope == nil || old.scope.manager != r.cursor.pool.manager {
		return nil, nil, ErrDomainPolicyTCPConsumer
	}
	child := old.scope.contextWith(parent)
	derived := *r
	derived.ctx, derived.prior = child, old
	derived.self = &derived
	return child, &derived, nil
}

func (r *domainTCPSuccessorRead) current(ctx context.Context, witness *domainTCPPoolListenerWitness, old *XrayDomainTCPExecutionResource) error {
	if ctx == nil {
		return ErrDomainPolicyTCPConsumer
	}
	if r == nil || r.self != r || !reflect.TypeOf(ctx).Comparable() || r.ctx != ctx || r.prior != old || old == nil || old == r.process || witness != r.witness || witness == nil || witness.resource != r.process || witness.cursor != r.cursor {
		return errors.Join(ErrDomainPolicyTCPConsumer, ctx.Err())
	}
	return errors.Join(r.rootCurrent(r.rootCtx), xraySelectedTCPFinite(ctx), ctx.Err())
}

func (r *domainTCPSuccessorRead) derive(ctx, processCtx context.Context, witness *domainTCPPoolListenerWitness, old *XrayDomainTCPExecutionResource) (*xrayDomainTCPFileObservation, func(), error) {
	if err := r.current(ctx, witness, old); err != nil {
		return nil, nil, err
	}
	// processCtx was just created by SAME successor.processReadContext from
	// this exact tracked prior context. Existing original process custody and
	// bounded view derivation still authenticate/revoke the child observation.
	nested, revoke, err := r.files.forOriginalProcessRead(r.rootCtx, processCtx, r.process)
	if err != nil {
		return nil, nil, err
	}
	domainTCPMeasure("successor-listener-derived-read")(0)
	return nested, revoke, nil
}
