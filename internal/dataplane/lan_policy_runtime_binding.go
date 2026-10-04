package dataplane

import (
	"context"
	"errors"
	"slices"
)

// LANPolicyReceiptBinding is the existing Manager participant's binding to the
// common mixed receipt. It owns no root, journal, worker or independent epoch.
// The participant supplies its trusted frozen Plan.LAN and retained root for
// every call, and durably preserves the promoted reference before retiring its
// transaction directory. Runner must consume common admission at process start.
type LANPolicyReceiptBinding struct {
	Runtime      *LANPolicyRuntime
	ApplyGuard   func(context.Context, *LANPolicyRuntimePlan, LANPolicyEffect) error
	CleanupGuard func(context.Context, *LANPolicyRuntimePlan, LANPolicyEffect) error
	// RetireCheck proves ALL routing/filter/DNS/NFQ/capture consumers settled.
	// A remaining or unknown consumer retains this gate, even if its kernel
	// rules do not directly reference the gate chain.
	RetireCheck func(context.Context, *LANPolicyRuntimePlan) error
	options     policyAdditionOptions // package tests only; no config/HTTP source
}

func cloneLANPolicyEffect(e LANPolicyEffect) LANPolicyEffect {
	e.Add, e.Delete, e.Needs = slices.Clone(e.Add), slices.Clone(e.Delete), slices.Clone(e.Needs)
	return e
}

// LANPolicyEffectsPlan derives commands only from the validated typed payload.
// Receipt argv are comparisons, never a command or deletion authority source.
func LANPolicyEffectsPlan(plan *LANPolicyRuntimePlan) (PolicyEffectPlan, error) {
	if err := ValidateLANPolicyRuntime(plan); err != nil {
		return PolicyEffectPlan{}, err
	}
	p := CloneLANPolicyRuntime(plan)
	effects, err := p.Effects()
	if err != nil {
		return PolicyEffectPlan{}, err
	}
	mixed := PolicyEffectPlan{Generation: p.Generation, Effects: make([]PolicyEffect, len(effects))}
	for i, e := range effects {
		mixed.Effects[i] = PolicyEffect{Tool: PolicyEffectTool(e.Tool), Add: slices.Clone(e.Add), Delete: slices.Clone(e.Delete), Needs: slices.Clone(e.Needs)}
	}
	if _, err := PolicyEffectPlanDigest(mixed); err != nil {
		return PolicyEffectPlan{}, err
	}
	return mixed, nil
}

type lanPolicyReceiptCall struct {
	plan    *LANPolicyRuntimePlan
	lan     LANPolicyRuntime
	mixed   PolicyEffectPlan
	runtime PolicyEffectRuntime
}

func (b *LANPolicyReceiptBinding) prepare(ctx context.Context, plan *LANPolicyRuntimePlan, cleanup bool) (*lanPolicyReceiptCall, error) {
	if b == nil || b.Runtime == nil || b.ApplyGuard == nil || b.CleanupGuard == nil || b.RetireCheck == nil || ValidateLANPolicyRuntime(plan) != nil {
		return nil, ErrLANPolicyRuntime
	}
	c := &lanPolicyReceiptCall{plan: CloneLANPolicyRuntime(plan), lan: *b.Runtime}
	if err := c.lan.checkTools(ctx, c.plan); err != nil {
		return nil, err
	}
	var err error
	c.mixed, err = LANPolicyEffectsPlan(c.plan)
	if err != nil {
		return nil, err
	}
	effects, err := c.plan.Effects()
	if err != nil {
		return nil, err
	}
	guard := b.ApplyGuard
	if cleanup {
		guard = b.CleanupGuard
	}
	retire := b.RetireCheck
	c.runtime = PolicyEffectRuntime{
		Runner:    c.lan.Runner,
		Tools:     PolicyEffectTools{IP: c.lan.IP, IPTables: c.lan.IPTables, IP6Tables: c.lan.IP6Tables},
		Preflight: func(ctx context.Context) error { return c.lan.Preflight(ctx, c.plan) },
		ExactPresence: func(ctx context.Context, index int) (int, error) {
			if index < 0 || index >= len(effects) {
				return 0, ErrLANPolicyRuntime
			}
			count, foreign, err := c.lan.InspectEffect(ctx, c.plan, effects[index])
			if foreign || count < 0 || count > 1 {
				return 0, errors.Join(err, ErrLANPolicyRuntime)
			}
			return count, err
		},
		BeforeDelete: func(ctx context.Context, index int) error {
			if index < 0 || index >= len(effects) {
				return ErrLANPolicyRuntime
			}
			if err := retire(ctx, CloneLANPolicyRuntime(c.plan)); err != nil {
				return err
			}
			return c.lan.BeforeDelete(ctx, c.plan, effects[index])
		},
		Guard: func(ctx context.Context, index int) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if index < 0 || index >= len(effects) {
				return ErrLANPolicyRuntime
			}
			return guard(ctx, CloneLANPolicyRuntime(c.plan), cloneLANPolicyEffect(effects[index]))
		},
	}
	return c, nil
}

func (b *LANPolicyReceiptBinding) Apply(ctx context.Context, plan *LANPolicyRuntimePlan, root string) error {
	c, err := b.prepare(ctx, plan, false)
	if err != nil {
		return err
	}
	if err := applyPolicyEffects(ctx, c.runtime, c.mixed, root, b.options); err != nil {
		return err
	}
	if err := c.lan.Verify(ctx, c.plan); err != nil {
		return err // Manager retains the receipt and settles known/unknown state
	}
	return c.runtime.Guard(ctx, len(c.mixed.Effects)-1)
}

func (b *LANPolicyReceiptBinding) Remove(ctx context.Context, plan *LANPolicyRuntimePlan, root string) error {
	c, err := b.prepare(ctx, plan, true)
	if err != nil {
		return err
	}
	// Refuse the whole retire before changing receipt grants; check again at
	// every deletion boundary because consumers outside Needs can change.
	if err := b.RetireCheck(ctx, CloneLANPolicyRuntime(c.plan)); err != nil {
		return err
	}
	if err := removePolicyEffects(ctx, c.runtime, c.mixed, root, b.options); err != nil {
		return err
	}
	for index := range c.mixed.Effects {
		count, err := c.runtime.ExactPresence(ctx, index)
		if err != nil || count != 0 {
			return errors.Join(err, ErrLANPolicyRuntime)
		}
	}
	return c.runtime.Guard(ctx, 0)
}

func (b *LANPolicyReceiptBinding) Inspect(ctx context.Context, plan *LANPolicyRuntimePlan, root string) (PolicyAdditionStatus, error) {
	if b == nil {
		return PolicyAdditionStatus{}, ErrLANPolicyRuntime
	}
	expected, err := LANPolicyEffectsPlan(plan)
	if err != nil {
		return PolicyAdditionStatus{}, err
	}
	return inspectPolicyEffects(ctx, expected, root, b.options)
}

func (b *LANPolicyReceiptBinding) Promote(ctx context.Context, plan *LANPolicyRuntimePlan, source, destination string) error {
	c, err := b.prepare(ctx, plan, false)
	if err != nil {
		return err
	}
	if err := c.runtime.Guard(ctx, len(c.mixed.Effects)-1); err != nil {
		return err
	}
	if err := c.lan.Verify(ctx, c.plan); err != nil {
		return err
	}
	if err := promotePolicyEffects(ctx, c.mixed, source, destination, b.options); err != nil {
		return err
	}
	return c.runtime.Guard(ctx, len(c.mixed.Effects)-1)
}
