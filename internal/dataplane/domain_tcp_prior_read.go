package dataplane

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
)

// One comparePrior read between journal writes. The publisher can hold the
// new scope/process mutexes, so this carrier checks only original associations
// and held files. Each prior reader still performs its independent process,
// listener, receipt, registry and kernel comparisons. It grants no publication,
// command, cleanup or forward authority. Fixed standalone readonly comparisons
// may additionally carry it in their own derived context; that context is
// revoked before returning to a journal writer, command or publication.
type domainTCPPriorReadKey struct{}

type domainTCPPriorReadLoan struct {
	self       *domainTCPPriorReadLoan
	cursor     *domainTCPGlobalSuccessor
	witness    *domainTCPPoolListenerWitness
	process    *XrayDomainTCPExecutionResource
	material   *XrayDomainTCPOperationMaterial
	child      *xraySelectedTCPProcess
	ctx        context.Context
	files      *xrayDomainTCPFileObservation
	bytes      *domainTCPSuccessorByteComparison
	open       atomic.Bool
	contextual bool
}

func domainTCPHasPriorRead(ctx context.Context) bool {
	return ctx != nil && ctx.Value(domainTCPPriorReadKey{}) != nil
}

func (l *domainTCPPriorReadLoan) sourcesCurrent(ctx context.Context) error {
	if ctx == nil {
		return ErrDomainPolicyTCPConsumer
	}
	if l == nil || l.contextual && ctx.Value(domainTCPPriorReadKey{}) != l || !l.contextual && domainTCPHasPriorRead(ctx) {
		return ErrDomainPolicyTCPConsumer
	}
	if l == nil || l.self != l || !reflect.TypeOf(ctx).Comparable() || ctx != l.ctx || xraySelectedTCPFinite(ctx) != nil ||
		ctx.Value(domainTCPPreAddKey{}) != nil || ctx.Value(domainTCPGuardReadKey{}) != nil ||
		ctx.Value(domainTCPBaselineCleanupKey{}) != nil || ctx.Value(domainTCPCaptureCleanupKey{}) != nil || ctx.Value(domainTCPFailureCleanupKey{}) != nil ||
		l.cursor == nil || l.cursor.original() != nil || l.witness == nil || l.witness.self != l.witness || l.cursor.listener.Load() != l.witness ||
		l.witness.cursor != l.cursor || l.witness.resource != l.process || l.process == nil || l.process.self != l.process ||
		l.process.scope != l.cursor.scope || l.process.records != l.cursor.records || l.process.descriptorsClosed.Load() ||
		l.material == nil || l.process.material != l.material || l.material.self != l.material || l.material.resource != l.process ||
		l.child == nil || l.child.self != l.child || l.process.child != l.child || l.witness.process != l.child || l.child.closed.Load() ||
		l.witness.ctx == nil || !sameNetworkPolicyDependency(l.witness.ctx, l.cursor.scope.ctx) || l.witness.ctx.Err() != nil {
		return errors.Join(ErrDomainPolicyTCPConsumer, ctx.Err())
	}
	select {
	case <-l.child.done:
		return ErrXrayDomainTCPOriginal
	default:
		return ctx.Err()
	}
}

func (l *domainTCPPriorReadLoan) current(ctx context.Context) error {
	if l == nil || !l.open.Load() || l.files == nil {
		return ErrDomainPolicyTCPConsumer
	}
	return errors.Join(l.sourcesCurrent(ctx), l.files.current(ctx, l.process))
}

// The unchanged full comparison is also the fallback before a listener exists,
// after its actual join, during cleanup, or when the bounded image slot is busy.
// No loan survives this call or crosses either original journal writer.
func (c *domainTCPGlobalSuccessor) comparePriorInFileObservation(ctx context.Context, after bool) error {
	fallback := func() error { return c.comparePriorWithSuccessorRead(ctx, after, nil) }
	if ctx == nil || c == nil || c.original() != nil {
		return ErrPolicyAdditionUnknown
	}
	if domainTCPHasPriorRead(ctx) {
		return ErrPolicyAdditionUnknown // A journal comparison cannot consume a readonly callback's loan.
	}
	if ctx.Value(domainTCPPreAddKey{}) != nil || ctx.Value(domainTCPGuardReadKey{}) != nil ||
		ctx.Value(domainTCPBaselineCleanupKey{}) != nil || ctx.Value(domainTCPCaptureCleanupKey{}) != nil || ctx.Value(domainTCPFailureCleanupKey{}) != nil {
		return fallback()
	}
	w := c.listener.Load()
	if w == nil {
		return fallback()
	}
	if w.resource == nil || w.process == nil {
		return ErrXrayDomainTCPOriginal
	}
	select {
	case <-w.process.done:
		return fallback()
	default:
	}
	p := w.resource
	l := &domainTCPPriorReadLoan{cursor: c, witness: w, process: p, material: p.material, child: w.process, ctx: ctx}
	l.self = l
	if err := l.sourcesCurrent(ctx); err != nil {
		return err
	}
	image := p.borrowFileObservationImage(ctx)
	if image == nil {
		return fallback()
	}
	return l.observeFiles(image, func(read *domainTCPSuccessorRead) error {
		return c.comparePriorWithSuccessorRead(ctx, after, read)
	})
}

func (l *domainTCPPriorReadLoan) observeFiles(image *xrayDomainTCPImageRead, use func(*domainTCPSuccessorRead) error) (result error) {
	if image != nil {
		defer func() {
			image.release()
			if l != nil && l.ctx != nil {
				result = errors.Join(result, image.contextCurrent(l.ctx))
			}
		}()
	}
	if l == nil || image == nil || use == nil || l.files != nil || l.bytes != nil || l.open.Load() || l.sourcesCurrent(l.ctx) != nil {
		return ErrDomainPolicyTCPConsumer
	}
	if err := l.process.filesCurrentForImageRead(l.ctx, nil, image); err != nil {
		return err
	}
	defer domainTCPMeasure("successor-prior-read-scope")(0)
	result = l.process.withFileObservationAfterOpeningImage(l.ctx, nil, func(files *xrayDomainTCPFileObservation) error {
		l.files = files
		comparison := &domainTCPSuccessorByteComparison{active: true, prior: l, image: image}
		comparison.self = comparison
		l.bytes = comparison
		l.open.Store(true)
		defer func() { l.open.Store(false); comparison.revoke() }()
		read := &domainTCPSuccessorRead{cursor: l.cursor, priorRead: l, files: files, process: l.process, witness: l.witness, rootCtx: l.ctx, ctx: l.ctx}
		read.self = read
		if err := read.rootCurrent(l.ctx); err != nil {
			return err
		}
		return errors.Join(use(read), read.rootCurrent(l.ctx), l.ctx.Err())
	}, image)
	return errors.Join(result, l.sourcesCurrent(l.ctx), l.ctx.Err())
}
