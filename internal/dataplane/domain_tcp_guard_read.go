package dataplane

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// A fixed pure guard's byte carrier, never a pre-Add effect/session grant.
// Only counterfactual row readers accept this key; command admission does not.
type domainTCPGuardReadKey struct{}
type domainTCPGuardReadLoan struct {
	self                              *domainTCPGuardReadLoan
	owner                             *DomainTCPOriginalScope
	baseline                          *syntheticBaselineExecutionResource
	capture                           *domainTCPCaptureExecutionResource
	process                           *XrayDomainTCPExecutionResource
	material                          *XrayDomainTCPOperationMaterial
	binding                           *SyntheticDNSExecutionBinding
	scope                             *executionResourceScope
	mapping                           *dnscontrol.SyntheticDNSMapping
	tools                             *SyntheticDNSCommandTools
	backend                           *BackendInventory
	source, backendRunner, toolRunner any
	cursor                            *domainTCPGlobalSuccessor
	witness                           *domainTCPPoolListenerWitness
	parent, ctx                       context.Context
	files                             *xrayDomainTCPFileObservation
	open                              atomic.Bool
	bytes                             *domainTCPSuccessorByteComparison
}

// Local associations only: safe while a byte reader holds its comparison lock.
// Full source/process/kernel authority still comes from the unchanged guard.
func (l *domainTCPGuardReadLoan) sourcesCurrent(ctx context.Context) error {
	if l == nil || l.self != l || ctx == nil || !reflect.TypeOf(ctx).Comparable() || ctx != l.ctx || ctx.Value(domainTCPGuardReadKey{}) != l || ctx.Value(domainTCPPreAddKey{}) != nil || domainTCPBaselineCurrentReadContext(l.parent, ctx) != nil || l.owner == nil || l.owner.self != l.owner || l.capture == nil || l.capture.self != l.capture || l.process == nil || l.process.self != l.process || l.baseline == nil || l.baseline.self != l.baseline || l.material == nil || l.binding == nil || l.scope == nil || l.tools == nil || l.backend == nil || l.cursor == nil || l.witness == nil {
		return ErrDomainPolicyTCPConsumer
	}
	r, p, b := l.capture, l.process, l.baseline
	if r.process != p || p.material != l.material || p.scope != l.scope || l.material.binding != l.binding || l.material.mapping != l.mapping || r.capture == nil || r.capture.owner != l.owner || r.capture.xray == nil || r.capture.xray.resource != p || r.mapping != l.mapping || r.tools != l.tools || r.backend != l.backend || b.capture != r.capture || b.binding != l.binding || b.mapping != l.mapping || b.tools != l.tools || b.backend != l.backend || l.scope.domainSuccessor != l.cursor || l.cursor.scope != l.scope || l.cursor.listener.Load() != l.witness || l.witness.cursor != l.cursor || l.witness.resource != p || !sameNetworkPolicyDependency(l.owner.source, l.source) || !sameNetworkPolicyDependency(l.backend.reader.Runner, l.backendRunner) || !sameNetworkPolicyDependency(l.tools.Runner, l.toolRunner) {
		return ErrDomainPolicyTCPConsumer
	}
	l.owner.mu.Lock()
	same := !l.owner.closed && l.owner.process == p && l.owner.capture == r.capture && l.owner.captureResource == r && l.owner.baseline == b && l.owner.binding == l.binding
	l.owner.mu.Unlock()
	if !same {
		return ErrDomainPolicyTCPConsumer
	}
	return ctx.Err()
}

func (l *domainTCPGuardReadLoan) current(ctx context.Context) error {
	if l == nil || !l.open.Load() || l.files == nil {
		return ErrDomainPolicyTCPConsumer
	}
	return errors.Join(l.sourcesCurrent(ctx), l.files.current(ctx, l.process))
}

func (r *domainTCPCaptureExecutionResource) observeOriginalGuardFiles(ctx context.Context, baseline *syntheticBaselineExecutionResource, use func(context.Context, *xrayDomainTCPFileObservation) error) (result error) {
	if ctx == nil || use == nil || ctx.Value(domainTCPGuardReadKey{}) != nil {
		return ErrDomainPolicyTCPConsumer
	}
	fallback := func() error {
		return r.observePreAddFiles(ctx, false, func(files *xrayDomainTCPFileObservation) error { return use(ctx, files) })
	}
	if ctx.Value(domainTCPPreAddKey{}) != nil || ctx.Value(domainTCPBaselineCleanupKey{}) != nil || ctx.Value(domainTCPCaptureCleanupKey{}) != nil || ctx.Value(domainTCPFailureCleanupKey{}) != nil {
		return fallback()
	}
	original, err := r.guardOriginalBaselineOwner(ctx, baseline)
	if err != nil {
		return err
	}
	if !original || r.process.scope == nil || r.process.scope.domainSuccessor == nil {
		return fallback()
	}
	p, cursor := r.process, r.process.scope.domainSuccessor
	witness := cursor.listener.Load()
	if witness == nil {
		return fallback()
	}
	owner := r.capture.owner.(*DomainTCPOriginalScope)
	l := &domainTCPGuardReadLoan{owner: owner, baseline: baseline, capture: r, process: p, material: p.material, binding: p.material.binding, scope: p.scope, mapping: r.mapping, tools: r.tools, backend: r.backend, source: owner.source, backendRunner: r.backend.reader.Runner, toolRunner: r.tools.Runner, cursor: cursor, witness: witness, parent: ctx}
	l.self = l
	l.ctx = context.WithValue(ctx, domainTCPGuardReadKey{}, l)
	if err := l.sourcesCurrent(l.ctx); err != nil {
		return err
	}
	image := p.borrowFileObservationImage(l.ctx)
	if image == nil {
		return fallback()
	}
	return l.observeFiles(image, use)
}

func (l *domainTCPGuardReadLoan) observeFiles(image *xrayDomainTCPImageRead, use func(context.Context, *xrayDomainTCPFileObservation) error) (result error) {
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
	defer domainTCPMeasure("successor-guard-read-scope")(0)
	result = l.process.withFileObservationAfterOpeningImage(l.ctx, nil, func(files *xrayDomainTCPFileObservation) error {
		l.files = files
		comparison := &domainTCPSuccessorByteComparison{active: true, guard: l, image: image}
		comparison.self = comparison
		l.bytes = comparison
		l.open.Store(true)
		defer func() { l.open.Store(false); comparison.revoke() }()
		if err := l.current(l.ctx); err != nil {
			return err
		}
		bodyErr := use(l.ctx, files)
		return errors.Join(bodyErr, l.current(l.ctx), l.parent.Err())
	}, image)
	return errors.Join(result, l.sourcesCurrent(l.ctx), l.parent.Err())
}
