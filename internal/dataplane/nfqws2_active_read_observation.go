package dataplane

import (
	"context"
	"errors"
)

// Only the already existing pure readback/removal predicates borrow tools.
// Actual COMMON publication, Add/Delete and process Start use their original
// caller context after this synchronous loan has revoked and joined readers.
func (b *NFQWSScopedBinding) observeActiveTools(ctx context.Context, p *NFQWSScopedPlan, use func(context.Context) error) error {
	if ctx == nil || use == nil {
		return ErrNFQWSScopedOwner
	}
	supplied := ctx.Value(nfqws2ActiveExecutionKey{})
	if supplied == nil {
		return use(ctx)
	}
	e, ok := supplied.(*nfqws2ActiveExecution)
	if !ok || e == nil || e.self != e {
		return ErrNFQWSScopedOwner
	}
	// Existing deliberately readonly binding copies retain full observations;
	// an original execution never lends its source to another binding.
	if e.binding != b {
		return use(ctx)
	}
	if e.material == nil || e.material.self != e.material || e.resource == nil || e.resource.plan != p || p == nil || p.spec.Probe != nil || e.material.adapter == nil || e.material.manager == nil {
		return ErrNFQWSScopedOwner
	}
	original, ok := e.inventory.reader.Runner.(nfqwsProbeToolObserver)
	if !ok {
		return use(ctx)
	} // Existing model/unsupported producer path.
	material, resource, runner := e.material, e.resource, e.inventory.reader.Runner
	identity, review := material.intent.NetworkIdentity, e.inventory.review
	same := func(c context.Context) error {
		if err := nfqws2ActiveOperation(c); err != nil {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		if e.material != material || material.self != material || material.execution != e || !material.executionBound || e.resource != resource || resource.plan != p || e.binding != b || identity != material.intent.NetworkIdentity || review != e.inventory.review || !sameNetworkPolicyDependency(runner, e.inventory.reader.Runner) {
			return ErrNFQWSScopedOwner
		}
		nfqws2ActiveAdapterMu.Lock()
		associated := material.adapter.activeExecution == e
		nfqws2ActiveAdapterMu.Unlock()
		if !associated {
			return ErrNFQWSScopedOwner
		}
		return nil
	}
	if err := same(ctx); err != nil {
		return err
	}
	result := original.WithReadOnlyToolObservation(ctx, identity, review, func(observed context.Context) error {
		if err := same(observed); err != nil {
			return err
		}
		result := use(observed)
		return errors.Join(result, same(observed))
	})
	return errors.Join(result, same(ctx))
}
