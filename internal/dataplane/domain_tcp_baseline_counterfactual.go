package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

func (r *domainTCPBaselineExecutionResource) receiptAbsent() error {
	if r == nil || r.kernel == nil || r.kernel.capture == nil {
		return ErrDomainTCPBaselineKernel
	}
	s := r.kernel.capture.process.scope
	for _, name := range []string{policyAdditionFile, policyAdditionLock} {
		if _, err := s.owned.Stat(filepath.Join(r.relative, name)); !errors.Is(err, os.ErrNotExist) {
			return ErrDomainTCPBaselineKernel
		}
	}
	return nil
}

// The original COMMON borrow/held complete receipt supplies the per-effect
// states. Exact rows while merely planned and partial unknowns stay visible
// as a refusal; matching JSON or a freed table cannot mint this owner.
func (r *domainTCPBaselineExecutionResource) counterfactual(ctx context.Context, image DomainTCPBaselineReadImage, rows []backendInventoryRow) (DomainTCPBaselineReadImage, []backendInventoryRow, error) {
	if err := r.registered(ctx); err != nil {
		return image, nil, err
	}
	if r.kernel.flow.Load() != r {
		return image, nil, ErrDomainTCPBaselineKernel
	}
	filtered, remaining, counts, err := domainTCPBaselineFlowReadback(image, rows, r.definition.flowSpec())
	if err != nil {
		return image, nil, err
	}
	check := func(states []string) error {
		if len(states) != len(counts) {
			return ErrDomainTCPBaselineKernel
		}
		for i, state := range states {
			switch state {
			case "added":
				if counts[i] != 1 {
					return ErrDomainTCPBaselineKernel
				}
			case "planned", "intent":
				if counts[i] != 0 {
					return ErrDomainTCPBaselineKernel
				}
			default:
				return ErrDomainTCPBaselineKernel
			}
		}
		return nil
	}
	borrow, present, err := observeBorrowedPolicyEffects(ctx, r.effects, r.root)
	if err != nil {
		return image, nil, err
	}
	if present {
		defer borrow.close()
		states := borrow.states
		if borrow.absent {
			states = make([]string, len(counts))
			for i := range states {
				states[i] = "planned"
			}
		}
		if err := check(states); err != nil {
			return image, nil, err
		}
		return filtered, remaining, errors.Join(borrow.current(ctx), r.registered(ctx))
	}
	if r.receiptAbsent() == nil {
		for _, count := range counts {
			if count != 0 {
				return image, nil, ErrDomainTCPBaselineKernel
			}
		}
		return filtered, remaining, errors.Join(r.receiptAbsent(), r.registered(ctx))
	}
	receipt, err := observeNetworkPolicyEffects(ctx, r.effects, r.root, policyAdditionOptions{})
	defer receipt.close()
	s := receipt.status
	if err != nil || !s.Complete || s.Unknown || s.Removed || s.Promoted || s.Pending != 0 || s.Cleaned != 0 || s.Added != len(counts) {
		return image, nil, errors.Join(ErrDomainTCPBaselineKernel, err)
	}
	for _, count := range counts {
		if count != 1 {
			return image, nil, ErrDomainTCPBaselineKernel
		}
	}
	return filtered, remaining, errors.Join(receipt.current(), r.registered(ctx))
}
