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

// Both row predicates refer to the same actual backend and network identity.
// ReadWithFiles already checks completeness and removes only the original
// successor's authenticated predecessors. The current capture's receipts
// are checked before projecting its own rows out of the baseline picture.
func (i *syntheticBaselineKernelInspector) checkPreparedAtCaptureAdd(ctx context.Context, capture *domainTCPCaptureExecutionResource, index int, files *xrayDomainTCPFileObservation) error {
	if capture == nil || index < 0 || index >= len(capture.effects.Effects) {
		return ErrSyntheticBaselineTransition
	}
	return i.comparePreparedWithCaptureInventory(ctx, capture, files, func(rows []backendInventoryRow) error {
		count, err := domainTCPCapturePresence(rows, capture.effects, index)
		if err != nil || count != 0 {
			return errors.Join(ErrPolicyAdditionReceipt, err)
		}
		return nil
	})
}

func (i *syntheticBaselineKernelInspector) comparePreparedWithCaptureInventory(ctx context.Context, capture *domainTCPCaptureExecutionResource, files *xrayDomainTCPFileObservation, compareCapture func([]backendInventoryRow) error) error {
	if i == nil || i.self != i || ctx == nil || ctx.Err() != nil || i.mapping == nil || i.identity == nil ||
		capture == nil || capture.self != capture || i.capture.Load() != capture || capture.backend != i.backend || capture.mapping != i.mapping ||
		capture.process == nil || capture.process.scope == nil || capture.process.scope.networkIdentity != i.identity ||
		capture.process.scope.domainSuccessor != i.successor || files == nil || compareCapture == nil {
		return ErrSyntheticBaselineTransition
	}
	if err := i.mapping.Current(ctx); err != nil {
		return err
	}
	if err := i.identity.check(ctx); err != nil {
		return err
	}
	view, err := capture.readWithFiles(ctx, files)
	if err != nil {
		return err
	}
	if err := i.identity.check(ctx); err != nil {
		return err
	}
	if err := compareCapture(view.Rows); err != nil {
		return err
	}
	baselineRows, err := capture.counterfactualRows(ctx, view.Rows)
	if err != nil {
		return err
	}
	if err := syntheticBaselinePreparedKernel(baselineRows, i.plan); err != nil {
		return err
	}
	if i.capture.Load() != capture {
		return ErrSyntheticBaselineTransition
	}
	return errors.Join(i.mapping.Current(ctx), i.identity.check(ctx), ctx.Err())
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
