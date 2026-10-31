package dataplane

import (
	"context"
	"errors"
	"path/filepath"
)

type domainTCPCaptureCleanupKey struct{}

func (r *domainTCPCaptureExecutionResource) cleanupCurrent(ctx context.Context) error {
	if ctx == nil || ctx.Value(domainTCPCaptureCleanupKey{}) != r {
		return ErrDomainPolicyTCPConsumer
	}
	if err := r.registered(ctx); err != nil {
		return err
	}
	if err := r.process.records.current(ctx, true); err != nil {
		return err
	}
	if err := r.tools.Runner.CheckSyntheticDNS(ctx, r.tools.Identity); err != nil {
		return err
	}
	return r.process.scope.networkIdentity.check(ctx)
}

// Remove the local capture ONLY after its actual source and all accepted
// handlers joined. The original acknowledged standby remains installed; this
// is not permission to retire caches, conntrack or reuse a synthetic address.
func (r *domainTCPCaptureExecutionResource) retire(ctx context.Context, baseline *syntheticBaselineExecutionResource, kernel *domainTCPBaselineKernelOwner) error {
	if r == nil || r.self != r || baseline == nil || baseline.self != baseline || baseline.capture != r.capture || baseline.mapping != r.mapping || baseline.inspector == nil || kernel == nil || kernel.capture != r || kernel.baseline != baseline {
		return ErrDomainPolicyTCPConsumer
	}
	ctx = context.WithValue(ctx, domainTCPCaptureCleanupKey{}, r)
	if err := r.cleanupCurrent(ctx); err != nil {
		return err
	}
	if err := r.capture.retirement.Joined(ctx); err != nil {
		return err
	}
	if _, err := baseline.retirement.ClosedObservation(ctx); err != nil {
		return err
	}
	if kernel.flow.Load() != nil {
		return ErrDomainTCPBaselineKernel
	}
	// Preserve the exact original restorative dependency throughout cutover.
	checkStandby := func(c context.Context) error {
		if err := r.cleanupCurrent(c); err != nil {
			return err
		}
		receipt, err := observeNetworkPolicyEffects(c, baseline.effects, baseline.root, policyAdditionOptions{})
		defer receipt.close()
		status := receipt.status
		if err != nil || !status.Complete || status.Unknown || status.Removed || status.Promoted || status.Pending != 0 || status.Cleaned != 0 || status.Added != len(baseline.effects.Effects) {
			return errors.Join(ErrSyntheticBaselineTransition, err)
		}
		view, err := r.read(c)
		if err != nil {
			return err
		}
		for i := range baseline.effects.Effects {
			count, e := syntheticBaselineExactPresence(view.Rows, baseline.effects, i)
			if e != nil || count != 1 {
				return ErrSyntheticBaselineTransition
			}
		}
		return receipt.current()
	}
	if err := checkStandby(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	runtime := PolicyEffectRuntime{Runner: &domainTCPCaptureEffectRunner{r}, Tools: PolicyEffectTools{IPTables: r.tools.IPTables}, Guard: func(c context.Context, _ int) error { return checkStandby(c) }, Preflight: checkStandby,
		ExactPresence: func(c context.Context, i int) (int, error) {
			view, err := r.read(c)
			if err != nil {
				return 0, err
			}
			return domainTCPCapturePresence(view.Rows, r.effects, i)
		},
		BeforeDelete: func(c context.Context, i int) error {
			view, err := r.read(c)
			if err != nil {
				return err
			}
			for child, e := range r.effects.Effects {
				for _, parent := range e.Needs {
					if parent == i {
						count, err := domainTCPCapturePresence(view.Rows, r.effects, child)
						if err != nil || count != 0 {
							return ErrDomainPolicyTCPConsumer
						}
					}
				}
			}
			return checkStandby(c)
		}}
	if err := RemovePolicyEffectsWithReceipt(ctx, runtime, r.effects, r.root); err != nil {
		return err
	}
	receipt, err := observeNetworkPolicyEffects(ctx, r.effects, r.root, policyAdditionOptions{})
	defer receipt.close()
	if err != nil || !receipt.status.Removed || receipt.status.Unknown {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	view, err := r.read(ctx)
	if err != nil {
		return err
	}
	for i := range r.effects.Effects {
		count, e := domainTCPCapturePresence(view.Rows, r.effects, i)
		if e != nil || count != 0 {
			return ErrDomainPolicyTCPConsumer
		}
	}
	if err := receipt.current(); err != nil {
		return err
	}
	s := r.process.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.execution.Resources {
		record := &s.execution.Resources[i]
		if record.ID == filepath.Base(r.relative) {
			if record.State != "prepared" {
				return ErrDomainPolicyTCPConsumer
			}
			record.State, record.Phase = "removed", "removed"
			if err := s.persist(); err != nil {
				return err
			}
			if !baseline.inspector.capture.CompareAndSwap(r, nil) {
				return ErrDomainPolicyTCPConsumer
			}
			return nil
		}
	}
	return ErrDomainPolicyTCPConsumer
}
