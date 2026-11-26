package dataplane

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sort"
)

// Full owner/endpoint/routing reads occur outside the collector boundary. The
// inner comparison uses only actual original COMMON publications and files.
type networkPolicyWGObservation struct {
	owner       *wgOperationOwner
	publication *wgCommonPublication
	ref         warpWGPolicyReference
	effects     wgNetworkEffects
	states      []string
	borrowed    bool
}

func (c *NetworkPolicyChecks) wgConsumers(ctx context.Context, lan *LANPolicyRuntimePlan) ([]networkPolicyWGObservation, error) {
	raw := ctx.Value(wgOperationOwnerKey{})
	if raw == nil {
		return nil, nil
	}
	o, ok := raw.(*wgOperationOwner)
	if !ok || o == nil || o.self != o || o.scope == nil || o.scope.wgOwner != o || o.scope.manager != c.manager || ctx.Value(wgOperationMaterialKey{}) != o.material || c.adapters[o.adapter.ID()] != o.adapter || !reflect.DeepEqual(o.scope.plan.LAN, lan) {
		return nil, ErrWGOperationOwner
	}
	if err := o.check(ctx, wgOperationCleanup(ctx)); err != nil {
		return nil, err
	}
	o.commonMu.Lock()
	var publications []*wgCommonPublication
	for _, p := range o.common {
		if !p.status.Promoted && !p.status.Removed {
			publications = append(publications, p)
		}
	}
	o.commonMu.Unlock()
	sort.Slice(publications, func(i, j int) bool { return publications[i].path < publications[j].path })
	var observations []networkPolicyWGObservation
	for _, p := range publications {
		if p.owner != o || p.current(ctx) != nil || o.adapter.verifyWGNetworkReferenceScope(o.scope.plan, p.ref) != nil {
			return nil, ErrPolicyAdditionReceipt
		}
		effects, err := o.adapter.compileWGNetworkEffects(p.ref)
		if err != nil || !reflect.DeepEqual(effects.plan, p.effects) {
			return nil, errors.Join(ErrPolicyAdditionReceipt, err)
		}
		ob := networkPolicyWGObservation{owner: o, publication: p, ref: p.ref, effects: effects, states: append([]string(nil), p.states...)}
		if b, present, err := observeBorrowedPolicyEffects(ctx, effects.plan, p.path); present {
			if err != nil || b.borrow == nil || b.current(ctx) != nil || b.document == nil || !sameWGCommonBorrow(p, b) {
				b.close()
				return nil, errors.Join(ErrPolicyAdditionReceipt, err)
			}
			ob.states, ob.borrowed = append([]string(nil), b.states...), true
			b.close()
		}
		if err := ob.currentRuntime(ctx); err != nil {
			return nil, err
		}
		observations = append(observations, ob)
	}
	return observations, nil
}

func sameWGCommonBorrow(p *wgCommonPublication, b policyEffectBorrowObservation) bool {
	return p != nil && b.fileInfo != nil && p.fileInfo != nil && reflect.DeepEqual(p.canonical, b.canonical) && os.SameFile(p.fileInfo, b.fileInfo)
}

func (o networkPolicyWGObservation) currentFiles(ctx context.Context) error {
	if o.owner == nil || o.owner.self != o.owner || o.owner.scope == nil || o.owner.scope.wgOwner != o.owner || o.publication == nil || o.publication.owner != o.owner || !reflect.DeepEqual(o.states, o.publication.states) || !reflect.DeepEqual(o.ref, o.publication.ref) || !reflect.DeepEqual(o.effects.plan, o.publication.effects) {
		return ErrWGOperationOwner
	}
	return o.publication.current(ctx)
}

func (o networkPolicyWGObservation) currentRuntime(ctx context.Context) error {
	if err := o.currentFiles(ctx); err != nil {
		return err
	}
	a := o.owner.adapter
	runtime := a.wgNetworkEffectRuntime(o.ref, o.effects, false)
	for i := 0; i < o.effects.routing; i++ {
		n, err := runtime.ExactPresence(ctx, i)
		if err != nil || n > 1 || n < 0 {
			return errors.Join(ErrWGNetworkPolicy, err)
		}
		switch o.states[i] {
		case "added":
			if n != 1 {
				return ErrWGNetworkPolicy
			}
		case "planned", "removed":
			if n != 0 {
				return ErrWGNetworkPolicy
			}
		case "intent", "cleanup-intent":
			if !o.borrowed {
				return ErrPolicyAdditionReceipt
			}
		default:
			return ErrPolicyAdditionReceipt
		}
	}
	if err := a.verifyWGEndpoint(ctx, o.ref.Policy.WireGuardEndpoint, o.ref.FrozenLAN); err != nil {
		return err
	}
	return o.currentFiles(ctx)
}

func checkNetworkPolicyInventoryWithWG(s BackendInventorySnapshot, identity networkPolicyIdentity, lan *LANPolicyRuntimePlan, mode string, proxies []networkPolicyProxyObservation, stock []BackendInventoryRow, nfq []networkPolicyNFQObservation, xray []networkPolicyXraySelectedTCPObservation, wg []networkPolicyWGObservation) error {
	filtered := s
	filtered.Rows = append([]BackendInventoryRow(nil), s.Rows...)
	for _, ob := range wg {
		rows, _, err := ob.owner.adapter.wgNetworkInventoryReceiptAllowance(ob.ref, ob.effects, ob.states, ob.borrowed, s)
		if err != nil {
			return err
		}
		for _, row := range rows {
			key := wgNetworkInventoryRowKey(row)
			found := -1
			for i, actual := range filtered.Rows {
				if wgNetworkInventoryRowKey(actual) == key {
					if found >= 0 {
						return ErrNetworkPolicyConsumers
					}
					found = i
				}
			}
			if found < 0 {
				return ErrNetworkPolicyConsumers
			}
			filtered.Rows = append(filtered.Rows[:found], filtered.Rows[found+1:]...)
		}
	}
	return checkNetworkPolicyInventoryWithXray(filtered, identity.value, lan, mode, proxies, stock, nfq, xray)
}
