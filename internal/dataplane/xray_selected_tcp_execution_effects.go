package dataplane

import (
	"context"
	"errors"
	"os"
)

func (e *xraySelectedTCPExecution) policyRuntime(cleanup bool) PolicyEffectRuntime {
	r := e.resource
	guard := func(ctx context.Context, index int) error {
		if r == nil || index < 0 || index >= len(r.effects.Effects) || e.owners(ctx) != nil || !r.OriginalOperationContext(ctx) {
			return ErrXrayOperationOwner
		}
		return r.owner.checkHeld(ctx, cleanup)
	}
	read := func(ctx context.Context) (BackendInventorySnapshot, error) {
		if e.owners(ctx) != nil || r == nil || !r.OriginalOperationContext(ctx) {
			return BackendInventorySnapshot{}, ErrXrayOperationOwner
		}
		if err := e.checks.InventoryCheck(networkPolicyConsumerContext(ctx, e.plan), e.gate.identity.value, e.plan.LAN); err != nil {
			return BackendInventorySnapshot{}, err
		}
		return e.inventory.Read(ctx, e.gate.identity.value)
	}
	return PolicyEffectRuntime{Runner: e.gate.Binding.Runtime.Runner, Tools: PolicyEffectTools{IP: e.checks.tools[0], IPTables: e.checks.tools[1], IP6Tables: e.checks.tools[2]}, Guard: guard,
		Preflight: func(ctx context.Context) error { _, err := read(ctx); return err },
		ExactPresence: func(ctx context.Context, index int) (int, error) {
			if err := guard(ctx, index); err != nil {
				return 0, err
			}
			rows, _, err := xraySelectedTCPReceiptRows(r.effects, xraySelectedTCPAllAdded(r.effects), false)
			if err != nil || len(rows) != len(r.effects.Effects) {
				return 0, ErrPolicyAdditionReceipt
			}
			want, err := xraySelectedTCPNATRuleKey(rows[index])
			if err != nil {
				return 0, err
			}
			snapshot, err := read(ctx)
			if err != nil {
				return 0, err
			}
			count := 0
			for _, row := range snapshot.Rows {
				if !networkPolicyXraySelectedTCPRow(row) {
					continue
				}
				key, err := xraySelectedTCPNATRuleKey(row)
				if err != nil {
					return 0, err
				}
				if key == want {
					count++
				}
			}
			if count > 1 {
				return 0, ErrPolicyAdditionUnknown
			}
			return count, guard(ctx, index)
		},
		BeforeDelete: func(ctx context.Context, index int) error {
			if !cleanup {
				return ErrXrayOperationOwner
			}
			if err := guard(ctx, index); err != nil {
				return err
			}
			_, err := read(ctx)
			return err
		}}
}

func xraySelectedTCPAllAdded(plan PolicyEffectPlan) []string {
	states := make([]string, len(plan.Effects))
	for i := range states {
		states[i] = "added"
	}
	return states
}

func (e *xraySelectedTCPExecution) activate(ctx context.Context) error {
	if err := e.validate(ctx); err != nil {
		return err
	}
	e.mu.Lock()
	if e.started || e.retired || e.resource == nil {
		e.mu.Unlock()
		return ErrXrayOperationOwner
	}
	e.started = true
	r := e.resource
	e.mu.Unlock()
	bound, err := r.owner.context(networkPolicyConsumerContext(ctx, e.plan))
	if err != nil {
		return err
	}
	if err := e.checks.InventoryCheck(bound, e.gate.identity.value, e.plan.LAN); err != nil {
		return err
	}
	r.mu.Lock()
	err = r.startOriginalNative(bound)
	if err == nil {
		err = r.publishOriginalListener(bound)
	}
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if err := ApplyPolicyEffectsWithReceipt(bound, e.policyRuntime(false), r.effects, r.rootPath); err != nil {
		return err
	}
	if err := e.health(bound); err != nil {
		return err
	}
	r.scope.mu.Lock()
	i, err := r.matching()
	if err == nil && r.scope.execution.Resources[i].Phase != "listener-ready" {
		err = errXraySelectedTCPRuntime
	}
	if err == nil {
		r.scope.execution.Resources[i].Phase = "applied"
		err = r.scope.persist()
	}
	r.scope.mu.Unlock()
	return err
}

// Structural native health does not grant per-client service RouteEvidence.
// Manager's selected Sources reducer must keep that evidence unknown.
func (e *xraySelectedTCPExecution) health(ctx context.Context) error {
	if err := e.owners(ctx); err != nil {
		return err
	}
	e.mu.Lock()
	r := e.resource
	retired := e.retired
	e.mu.Unlock()
	if r == nil || retired {
		return ErrXrayOperationOwner
	}
	bound, err := r.owner.context(networkPolicyConsumerContext(ctx, e.plan))
	if err != nil {
		return err
	}
	if err := r.originalListenerCurrent(bound, false); err != nil {
		return err
	}
	r.commonMu.Lock()
	p := r.common
	err = ErrPolicyAdditionReceipt
	if p != nil && p.status.Complete && !p.status.Removed && !p.status.Unknown && !p.status.Promoted {
		err = p.current(bound)
	}
	r.commonMu.Unlock()
	if err != nil {
		return err
	}
	if err := e.checks.ConsumerCheck(bound, e.plan.LAN); err != nil {
		return err
	}
	return r.originalListenerCurrent(bound, false)
}

func (e *xraySelectedTCPExecution) commit(ctx context.Context) error { return e.health(ctx) }

func (e *xraySelectedTCPExecution) removeOriginalEffects(ctx context.Context) error {
	r := e.resource
	if r == nil || !r.OriginalOperationContext(ctx) {
		return ErrXrayOperationOwner
	}
	r.commonMu.Lock()
	p := r.common
	if p == nil {
		for _, name := range []string{policyAdditionFile, policyAdditionLock} {
			if _, err := r.root.Stat(name); !errors.Is(err, os.ErrNotExist) {
				r.commonMu.Unlock()
				return ErrPolicyAdditionUnknown
			}
		}
		r.commonMu.Unlock()
		return nil
	}
	err := p.current(ctx)
	removed, unknown := p.status.Removed, p.status.Unknown
	r.commonMu.Unlock()
	if err != nil || unknown {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	if removed {
		return nil
	}
	return RemovePolicyEffectsWithReceipt(ctx, e.policyRuntime(true), r.effects, r.rootPath)
}
