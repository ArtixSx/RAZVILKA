package dataplane

import (
	"context"
	"errors"
)

// This association permits no effect and retains no observation. Deliberate
// readonly binding copies may change their admission predicate, but must keep
// the exact original private network, runner, tools and active producer.
func (b *NFQWSScopedBinding) activeReadbackOwner(ctx context.Context, p *NFQWSScopedPlan) (*nfqws2ActiveExecution, error) {
	if b == nil || b.activeReadback == nil || b.AdditionalReadback != nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrNFQWSScopedOwner
	}
	e := b.activeReadback
	if e.self != e || ctx.Value(nfqws2ActiveExecutionKey{}) != e || e.material == nil || e.material.self != e.material || e.material.execution != e || !e.material.executionBound || e.resource == nil || e.resource.Plan() != p || p == nil || p.spec.Probe != nil || e.binding == nil || e.binding.activeReadback != e || e.binding.AdditionalReadback != nil || b.network == nil || b.network != e.binding.network || b.network.provider != e.material.provider || b.network.inventory.review != e.inventory.review || b.network.inventory.reader.Provider != e.inventory.reader.Provider || b.network.inventory.reader.NFTABI != e.inventory.reader.NFTABI || !sameNetworkPolicyDependency(b.network.inventory.reader.Runner, e.inventory.reader.Runner) || !sameNetworkPolicyDependency(b.Runner, e.runtimeFrozen.Runner) || b.Tools.IPTables != e.inventory.reader.IPTables || b.Tools.IP6Tables != e.inventory.reader.IP6Tables {
		return nil, ErrNFQWSScopedOwner
	}
	return e, nil
}

// The callback path performs additional(full capture), rules(full capture),
// additional(full capture). The original active additional predicate checks
// exactly the SAME inventory's completeness/identity. Retain its two full
// captures and every opening/closing owner callback; return the later capture
// as rules instead of doing a third intermediate capture. Nothing from the
// first capture is reused across callbacks. readFinalRules still collects its
// separate final image after all callbacks, as before.
func (b *NFQWSScopedBinding) readActiveRules(ctx context.Context, p *NFQWSScopedPlan) (nfqwsScopedReadImage, error) {
	defer measureNFQWSProbeContextPhase(ctx, nfqwsProbePhaseActiveReadPair)()
	var result nfqwsScopedReadImage
	for range 2 {
		e, err := b.activeReadbackOwner(ctx, p)
		if err != nil {
			return nfqwsScopedReadImage{}, err
		}
		if err := e.owners(ctx); err != nil {
			return nfqwsScopedReadImage{}, err
		}
		measure := measureNFQWSProbeContextPhase(ctx, nfqwsProbePhaseActiveInventory)
		image, err := b.network.rules(ctx, p)
		measure()
		// Always perform the closing original owner observation, including a
		// failed capture; no partial or stale image is returned on any failure.
		closing := e.owners(ctx)
		_, association := b.activeReadbackOwner(ctx, p)
		if err = errors.Join(err, closing, association, ctx.Err()); err != nil {
			return nfqwsScopedReadImage{}, err
		}
		result = image
	}
	return result, nil
}
