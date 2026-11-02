package dataplane

import (
	"context"
	"errors"
	"path/filepath"
)

func (r *domainTCPBaselineExecutionResource) cleanupCurrent(ctx context.Context) error {
	if ctx == nil || ctx.Value(domainTCPBaselineCleanupKey{}) != r {
		return ErrDomainTCPBaselineKernel
	}
	if err := r.registered(ctx); err != nil {
		return err
	}
	c := r.kernel.capture
	if err := c.tools.Runner.CheckSyntheticDNS(ctx, c.tools.Identity); err != nil {
		return err
	}
	return c.process.scope.networkIdentity.check(ctx)
}

// Called synchronously before the accepted handler releases its original
// gate/scope. Original descriptors close before reply routing is removed.
// Unknown close/COMMON results retain this exact owner and journal fence.
func (r *domainTCPBaselineExecutionResource) retire(ctx context.Context) error {
	if r == nil || r.self != r || ctx == nil {
		return ErrDomainTCPBaselineKernel
	}
	ctx = context.WithValue(ctx, domainTCPBaselineCleanupKey{}, r)
	if err := r.cleanupCurrent(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.native != nil {
		if err := r.native.closeNative(); err != nil {
			return err
		}
	}
	if r.started {
		c := r.kernel.capture
		runtime := PolicyEffectRuntime{Runner: &domainTCPBaselineEffectRunner{r}, Tools: PolicyEffectTools{IP: c.tools.IP, IPTables: c.tools.IPTables}, Guard: func(c context.Context, _ int) error { return r.cleanupCurrent(c) },
			Preflight: func(c context.Context) error { return r.cleanupCurrent(c) }, ExactPresence: func(c context.Context, i int) (int, error) {
				counts, err := r.effectCounts(c)
				if err != nil {
					return 0, err
				}
				return counts[i], nil
			}, BeforeDelete: func(c context.Context, _ int) error { return r.cleanupCurrent(c) }}
		if err := RemovePolicyEffectsWithReceipt(ctx, runtime, r.effects, r.root); err != nil {
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
		receipt, err := observeNetworkPolicyEffects(ctx, r.effects, r.root, policyAdditionOptions{})
		defer receipt.close()
		if err != nil || !receipt.status.Removed || receipt.status.Unknown {
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
		counts, err := r.effectCounts(ctx)
		if err != nil {
			return err
		}
		for _, count := range counts {
			if count != 0 {
				return ErrDomainTCPBaselineKernel
			}
		}
		if err := receipt.current(); err != nil {
			return err
		}
	}
	s := r.kernel.capture.process.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.execution.Resources {
		record := &s.execution.Resources[i]
		if record.ID == filepath.Base(r.relative) {
			if record.State != "prepared" {
				return ErrDomainTCPBaselineKernel
			}
			record.State, record.Phase = "removed", "removed"
			if !r.started {
				record.State, record.Phase = "unused", "unused"
			}
			if err := s.persist(); err != nil {
				return err
			}
			if !r.kernel.flow.CompareAndSwap(r, nil) {
				return ErrDomainTCPBaselineKernel
			}
			return nil
		}
	}
	return ErrDomainTCPBaselineKernel
}
