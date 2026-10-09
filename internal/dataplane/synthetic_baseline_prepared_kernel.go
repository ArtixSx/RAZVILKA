package dataplane

import (
	"context"
	"errors"
)

// CheckPrepared is one complete original kernel readback, distinct from the
// partial/absent checks used while COMMON Apply is still adding the plan. All
// four effects must coexist in that SAME image before capture/publication can
// depend on them. Firmware comparison here covers only pre-DNAT classic hooks;
// native routing/RPDB, post-DNAT filter and conntrack comparisons remain separate.
// This read-only component does not authenticate COMMON ACKs,
// register a resource, transfer its owner, publish DNS or settle removal.
func (i *syntheticBaselineKernelInspector) CheckPrepared(ctx context.Context) error {
	if i == nil || i.self != i || i.mapping == nil || ctx == nil || ctx.Err() != nil {
		return ErrSyntheticBaselineTransition
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrSyntheticBaselineTransition
	}
	if err := i.mapping.Current(ctx); err != nil {
		return err
	}
	view, err := i.read(ctx)
	if err != nil {
		return err
	}
	if err := syntheticBaselinePreparedKernel(view.Rows, i.plan); err != nil {
		return err
	}
	if err := i.mapping.Current(ctx); err != nil {
		return err
	}
	return errors.Join(i.identity.check(ctx), ctx.Err())
}

// Pure whole-image comparison for the actual inspector above. A DTO image or
// successful comparison alone cannot create that original mapping/reader or
// any COMMON, capture or publication capability.
func syntheticBaselinePreparedKernel(rows []backendInventoryRow, plan PolicyEffectPlan) error {
	if _, err := syntheticBaselineTupleFromPlan(plan); err != nil {
		return err
	}
	for index := range plan.Effects {
		count, err := syntheticBaselineExactPresence(rows, plan, index)
		if err != nil || count != 1 {
			return errors.Join(ErrSyntheticBaselineTransition, err)
		}
	}
	return syntheticBaselinePreDNATEquivalent(rows, plan)
}
