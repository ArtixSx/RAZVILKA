package dataplane

import (
	"context"
	"errors"
)

// A supplied parent belongs to an already-open accepted-prefix comparison.
// Keep that exact file/context path, including both original process bookends;
// it must never be replaced by a new image or a separately derived prior loan.
// Only a standalone mapping read with no parent opens its own prior bracket.
func (p *XrayDomainTCPExecutionResource) observeOriginalPriorFilesFrom(ctx context.Context, current bool, parent *xrayDomainTCPFileObservation, use func(context.Context, *xrayDomainTCPFileObservation) error) error {
	if ctx == nil || use == nil {
		return ErrDomainPolicyTCPConsumer
	}
	if parent == nil {
		return p.observeOriginalPriorFiles(ctx, current, use)
	}
	read := func(files *xrayDomainTCPFileObservation) error { return use(ctx, files) }
	if current {
		return p.withCurrentFileObservationFrom(ctx, parent, read)
	}
	return p.withNestedFileObservation(ctx, parent, read)
}

// Called only by fixed pure baseline/preparation/mapping comparisons. The original
// full process checks remain inside the byte bracket, in their original order.
// A typed successor loan prevents their nested prior-owner comparisons from
// reopening the SAME live successor image. Old owners still reread every byte
// of their independent held descriptors and all original kernel/receipt state.
func (p *XrayDomainTCPExecutionResource) observeOriginalPriorFiles(ctx context.Context, current bool, use func(context.Context, *xrayDomainTCPFileObservation) error) error {
	if ctx == nil || use == nil || domainTCPHasPriorRead(ctx) {
		return ErrDomainPolicyTCPConsumer
	}
	read := func(observed context.Context, files *xrayDomainTCPFileObservation) error {
		if current {
			if err := p.currentWithFiles(observed, files); err != nil {
				return err
			}
		}
		result := use(observed, files)
		if current {
			result = errors.Join(result, p.currentWithFiles(observed, files))
		}
		return errors.Join(result, observed.Err())
	}
	fallback := func() error {
		return p.withFileObservation(ctx, func(files *xrayDomainTCPFileObservation) error { return read(ctx, files) })
	}
	if p == nil || p.scope == nil || p.scope.domainSuccessor == nil ||
		ctx.Value(domainTCPPreAddKey{}) != nil || ctx.Value(domainTCPGuardReadKey{}) != nil ||
		ctx.Value(domainTCPBaselineCleanupKey{}) != nil || ctx.Value(domainTCPCaptureCleanupKey{}) != nil || ctx.Value(domainTCPFailureCleanupKey{}) != nil {
		return fallback()
	}
	cursor := p.scope.domainSuccessor
	w := cursor.listener.Load()
	if w == nil {
		return fallback()
	}
	if w.resource != p || w.process == nil {
		return ErrDomainPolicyTCPConsumer
	}
	select {
	case <-w.process.done:
		return fallback()
	default:
	}
	l := &domainTCPPriorReadLoan{cursor: cursor, witness: w, process: p, material: p.material, child: w.process, contextual: true}
	l.self = l
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	l.ctx = context.WithValue(life, domainTCPPriorReadKey{}, l)
	if err := l.sourcesCurrent(l.ctx); err != nil {
		return err
	}
	image := p.borrowFileObservationImage(l.ctx)
	if image == nil {
		return fallback()
	}
	return l.observeFiles(image, func(successor *domainTCPSuccessorRead) error {
		return read(successor.ctx, successor.files)
	})
}
