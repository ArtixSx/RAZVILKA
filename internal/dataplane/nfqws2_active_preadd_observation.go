package dataplane

import (
	"context"
	"errors"
	"reflect"
)

// Issued only inside the original active Apply, alongside its sole COMMON
// writer custodian. This is not an effect grant or a public callback wrapper.
type nfqws2ActivePreAddRead struct {
	self      *nfqws2ActivePreAddRead
	execution *nfqws2ActiveExecution
	material  *NFQWSActiveMaterial
	resource  *NFQWSExecutionResource
	binding   *NFQWSScopedBinding
	plan      *NFQWSScopedPlan
	root      string
	digest    string
	custody   *nfqwsPolicyRecovery
	runner    nfqwsScopedApplyRunner
}

type nfqws2ActivePreAddKey struct{}

func newNFQWSActivePreAddRead(e *nfqws2ActiveExecution, b *NFQWSScopedBinding, p *NFQWSScopedPlan, runtime PolicyEffectRuntime, plan PolicyEffectPlan, root string, c *nfqwsPolicyRecovery) (PolicyEffectRuntime, error) {
	issued, ok := runtime.Runner.(nfqwsScopedApplyRunner)
	if !ok || e == nil || e.binding != b || e.resource == nil || e.resource.Plan() != p || e.resource.Root() != root || c == nil || c.self != c || c.execution != e || c.preAdd != nil || issued.binding != b || issued.scoped != p || !reflect.DeepEqual(issued.plan, plan) || issued.tools != runtime.Tools || issued.guard == nil || runtime.nodeTransitOrigin != nil {
		return runtime, ErrNFQWSScopedOwner
	}
	digest, err := PolicyEffectPlanDigest(plan)
	if err != nil {
		return runtime, err
	}
	r := &nfqws2ActivePreAddRead{execution: e, material: e.material, resource: e.resource, binding: b, plan: p, root: root, digest: digest, custody: c, runner: issued}
	r.self = r
	c.preAdd = r
	runtime.Runner = r // Exact private pointer provenance, never function comparison.
	return runtime, nil
}

func (r *nfqws2ActivePreAddRead) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	// A copied/escaped read context never reaches even the Apply runner's
	// original command preflight, including after its source was revoked.
	if r == nil || r.self != r || ctx == nil || ctx.Value(nfqws2ActivePreAddKey{}) != nil {
		return nil, ErrNFQWSScopedOwner
	}
	return r.runner.Run(ctx, name, args...)
}

// Called under the original cursor mutex. It authenticates the actual writer
// and authored image; no reopened path or modeled receipt mints a read loan.
func (r *nfqws2ActivePreAddRead) current(ctx context.Context, s *policyEffectSession, runtime PolicyEffectRuntime, index int) error {
	if r == nil || r.self != r || r.binding == nil || r.resource == nil || r.execution == nil || ctx == nil || ctx.Err() != nil || s == nil || s.nfqRecovery != r.custody || r.custody == nil || r.custody.self != r.custody || r.custody.preAdd != r || r.custody.session != s || r.custody.execution != r.execution || r.custody.index != index || r.custody.entered || s.domainPreAdd != nil || s.nodeTransitPresence != nil || s.path != r.root || index < 0 || index >= len(s.doc.Steps) || s.doc.Steps[index].State != "intent" || runtime.Runner != r || runtime.Tools != r.runner.tools || ctx.Value(policyEffectReceiptBorrowKey{}) != s.borrow {
		return errors.Join(ErrPolicyAdditionUnknown, networkPolicyChecksContextError(ctx))
	}
	e, err := r.binding.activeReadbackOwner(ctx, r.plan)
	if err != nil || e != r.execution || e.binding != r.binding || e.material != r.material || e.resource != r.resource || e.partialRecovery != r.custody || r.resource.Root() != r.root || !reflect.DeepEqual(s.plan, r.runner.plan) {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	digest, err := PolicyEffectPlanDigest(s.plan)
	if err != nil || digest != r.digest {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	return r.custody.documentCurrent(ctx)
}

func (r *nfqws2ActivePreAddRead) observe(ctx context.Context, s *policyEffectSession, runtime PolicyEffectRuntime, index int) error {
	if ctx == nil || ctx.Value(nfqws2ActivePreAddKey{}) != nil {
		return ErrPolicyAdditionUnknown
	}
	if err := r.current(ctx, s, runtime, index); err != nil {
		return err
	}
	var measurement nfqwsPreAddMeasurement
	err := r.binding.observeActiveTools(ctx, r.plan, func(observed context.Context) error {
		read := context.WithValue(observed, nfqws2ActivePreAddKey{}, r)
		if err := r.current(read, s, runtime, index); err != nil {
			return err
		}
		// ExactPresence, Guard, ExactPresence, Guard run in their original
		// order, with fresh whole captures and all original source checks.
		result := measurement.sequence(read, s, runtime, index)
		return errors.Join(result, r.current(read, s, runtime, index))
	})
	// The original source closes its byte bookends and joins every read
	// before add() may set entered or invoke the unborrowed Run context.
	result := errors.Join(err, r.current(ctx, s, runtime, index), ctx.Err())
	measurement.closed(index, result)
	if result != nil {
		return errors.Join(ErrPolicyAdditionUnknown, result)
	}
	return nil
}
