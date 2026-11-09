package dataplane

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
)

// This private producer is installed only by original domain preparation. It
// lends immutable held bytes across the four existing readonly pre-Add calls;
// it never replaces a source/process/kernel observation or enters an effect.
type domainTCPPreAddRead struct {
	self     *domainTCPPreAddRead
	baseline *syntheticBaselineExecutionResource
	capture  *domainTCPCaptureExecutionResource
	owner    *DomainTCPOriginalScope
	process  *XrayDomainTCPExecutionResource
	root     string
	digest   string
	runner   NFQWS2Runner
}

type domainTCPPreAddKey struct{}
type domainTCPPreAddLoan struct {
	self  *domainTCPPreAddLoan
	read  *domainTCPPreAddRead
	ctx   context.Context
	files *xrayDomainTCPFileObservation
	open  atomic.Bool
}

func applyDomainTCPOriginalEffects(ctx context.Context, runtime PolicyEffectRuntime, capture *domainTCPCaptureExecutionResource, baseline *syntheticBaselineExecutionResource) error {
	if baseline == nil || baseline.self != baseline || baseline.capture == nil {
		return ErrSyntheticBaselineTransition
	}
	if err := baseline.local(ctx); err != nil {
		return err
	}
	plan, root := baseline.effects, baseline.root
	if capture != nil {
		plan, root = capture.effects, capture.root
	}
	owner, original := baseline.capture.owner.(*DomainTCPOriginalScope)
	_, toolsObserved := baseline.backend.reader.Runner.(domainTCPToolObserver)
	if !original || !toolsObserved {
		// Existing modeled/custom producers retain independent full-byte reads.
		return ApplyPolicyEffectsWithReceipt(ctx, runtime, plan, root)
	}
	if owner == nil || owner.self != owner || baseline.capture.xray == nil {
		return ErrDomainPolicyTCPConsumer
	}
	digest, err := PolicyEffectPlanDigest(plan)
	if err != nil {
		return err
	}
	read := &domainTCPPreAddRead{baseline: baseline, capture: capture, owner: owner, process: baseline.capture.xray.resource, root: root, digest: digest, runner: runtime.Runner}
	read.self = read
	if err := read.current(ctx, runtime, plan, root); err != nil {
		return err
	}
	return applyPolicyEffectsWithDomainRead(ctx, runtime, plan, root, policyAdditionOptions{}, read)
}

func (r *domainTCPPreAddRead) current(ctx context.Context, runtime PolicyEffectRuntime, plan PolicyEffectPlan, root string) error {
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(ErrDomainPolicyTCPConsumer, ctx.Err())
	}
	if r == nil || r.self != r || ctx == nil || ctx.Err() != nil || r.baseline == nil || r.baseline.local(ctx) != nil || r.owner == nil || r.owner.self != r.owner || r.process == nil || r.process.self != r.process || r.process.material == nil || r.baseline.capture.owner != r.owner || r.baseline.capture.xray == nil || r.baseline.capture.xray.resource != r.process || r.owner.binding != r.baseline.binding || r.process.material.binding != r.baseline.binding || root != r.root || !sameNetworkPolicyDependency(runtime.Runner, r.runner) {
		return ErrDomainPolicyTCPConsumer
	}
	r.owner.mu.Lock()
	sameOwner := !r.owner.closed && r.owner.process == r.process && r.owner.capture == r.baseline.capture && r.owner.baseline == r.baseline && (r.capture == nil || r.owner.captureResource == r.capture)
	r.owner.mu.Unlock()
	if !sameOwner {
		return ErrDomainPolicyTCPConsumer
	}
	wanted := r.baseline.effects
	if r.capture != nil {
		if r.capture.local(ctx) != nil || r.capture.process != r.process || r.capture.capture != r.baseline.capture || r.capture.mapping != r.baseline.mapping || r.capture.backend != r.baseline.backend || r.capture.tools != r.baseline.tools || r.capture.root != root {
			return ErrDomainPolicyTCPConsumer
		}
		runner, ok := runtime.Runner.(*domainTCPCaptureEffectRunner)
		if !ok || runner == nil || runner.resource != r.capture {
			return ErrDomainPolicyTCPConsumer
		}
		wanted = r.capture.effects
	} else {
		runner, ok := runtime.Runner.(*syntheticBaselineEffectRunner)
		if !ok || runner == nil || runner.resource != r.baseline || r.baseline.root != root {
			return ErrDomainPolicyTCPConsumer
		}
	}
	digest, err := PolicyEffectPlanDigest(plan)
	if err != nil || digest != r.digest || !reflect.DeepEqual(plan, wanted) || runtime.Tools.IPTables != r.baseline.tools.IPTables {
		return ErrDomainPolicyTCPConsumer
	}
	return nil
}

func (r *domainTCPPreAddRead) observe(ctx context.Context, session *policyEffectSession, runtime PolicyEffectRuntime, index int) error {
	if ctx == nil {
		return ErrPolicyAdditionUnknown
	}
	if ctx.Err() != nil {
		return errors.Join(ErrPolicyAdditionUnknown, ctx.Err())
	}
	if session == nil || session.domainPreAdd != r || index < 0 || index >= len(session.doc.Steps) || session.doc.Steps[index].State != "intent" {
		return ErrPolicyAdditionUnknown
	}
	if err := r.current(ctx, runtime, session.plan, session.path); err != nil {
		return errors.Join(ErrPolicyAdditionUnknown, err, ctx.Err())
	}
	if ctx.Value(domainTCPPreAddKey{}) != nil {
		return ErrPolicyAdditionUnknown
	}
	defer domainTCPMeasure("pre-add-original-read")(0)
	err := r.baseline.observeTools(ctx, func(observed context.Context) error {
		loan := &domainTCPPreAddLoan{read: r}
		loan.self = loan
		loan.ctx = context.WithValue(observed, domainTCPPreAddKey{}, loan)
		return r.process.withFileObservation(loan.ctx, func(files *xrayDomainTCPFileObservation) error {
			loan.files = files
			loan.open.Store(true)
			defer loan.open.Store(false)
			result := session.observeBeforeAddUnshared(loan.ctx, runtime, index)
			return errors.Join(result, r.current(loan.ctx, runtime, session.plan, session.path))
		})
	})
	if err != nil {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	if ctx.Err() != nil {
		return errors.Join(ErrPolicyAdditionUnknown, ctx.Err())
	}
	domainTCPMeasure("pre-add-original-read-complete")(0)
	return nil
}

// The private loan is accepted only by its original capture/baseline readers.
// A foreign, expired or escaped marker refuses; it never chooses fallback.
func withDomainTCPPreAddFiles(ctx context.Context, process *XrayDomainTCPExecutionResource, baseline *syntheticBaselineExecutionResource, capture *domainTCPCaptureExecutionResource, current bool, use func(*xrayDomainTCPFileObservation) error) error {
	if ctx == nil || use == nil || process == nil {
		return ErrDomainPolicyTCPConsumer
	}
	value := ctx.Value(domainTCPPreAddKey{})
	if value == nil {
		if current {
			return process.withCurrentFileObservation(ctx, use)
		}
		return process.withFileObservation(ctx, use)
	}
	loan, ok := value.(*domainTCPPreAddLoan)
	if !ok || loan == nil || loan.self != loan || !loan.open.Load() || !reflect.TypeOf(ctx).Comparable() || loan.ctx != ctx || loan.read == nil || loan.read.self != loan.read || loan.read.process != process || baseline != nil && loan.read.baseline != baseline || capture != nil && loan.read.capture != capture || baseline == nil && capture == nil || loan.files == nil || loan.files.current(ctx, process) != nil {
		return ErrDomainPolicyTCPConsumer
	}
	if current {
		if err := process.currentWithFiles(ctx, loan.files); err != nil {
			return err
		}
	}
	result := use(loan.files)
	if current {
		result = errors.Join(result, process.currentWithFiles(ctx, loan.files))
	}
	return errors.Join(result, loan.files.current(ctx, process), ctx.Err())
}

func (r *domainTCPCaptureExecutionResource) observePreAddFiles(ctx context.Context, current bool, use func(*xrayDomainTCPFileObservation) error) error {
	if r == nil || r.self != r {
		return ErrDomainPolicyTCPConsumer
	}
	return withDomainTCPPreAddFiles(ctx, r.process, nil, r, current, use)
}
