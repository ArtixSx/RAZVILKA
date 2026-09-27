package dataplane

import (
	"context"
	"errors"
	"reflect"
	"slices"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

func (a *ScopedDNSAdapter) appliedSettings(spec *ScopedDNSPlan) error {
	if a.DNS == nil || spec == nil || len(spec.Bindings) == 0 {
		return dnscontrol.ErrServiceDNSChanged
	}
	first := spec.Bindings[0]
	return a.DNS.VerifyServiceSelection(first.ServiceID, first.ProfileID)
}

func scopedDNSSettingsTargets(previous *scopedDNSState, next *ScopedDNSPlan, suspend bool) map[string]string {
	targets := map[string]string{}
	if previous != nil && previous.DNS != nil && len(previous.DNS.Bindings) > 0 {
		targets[previous.DNS.Bindings[0].ServiceID] = ""
		if suspend {
			targets[previous.DNS.Bindings[0].ServiceID] = previous.DNS.Bindings[0].ProfileID
		}
	}
	if next != nil && len(next.Bindings) > 0 {
		targets[next.Bindings[0].ServiceID] = next.Bindings[0].ProfileID
	}
	return targets
}

func (a *ScopedDNSAdapter) reviewSettings(previous *scopedDNSState, next *ScopedDNSPlan, suspend bool) ([]dnscontrol.ServiceSelectionReceipt, error) {
	if a.DNS == nil {
		return nil, dnscontrol.ErrServiceDNSChanged
	}
	targets := scopedDNSSettingsTargets(previous, next, suspend)
	ids := make([]string, 0, len(targets))
	for id := range targets {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if len(ids) == 0 {
		return nil, errors.New("no scoped DNS setting to own")
	}
	receipts := make([]dnscontrol.ServiceSelectionReceipt, 0, len(ids))
	for _, id := range ids {
		r, err := a.DNS.ReviewServiceSelection(id, targets[id])
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, r.Receipt())
	}
	return receipts, nil
}

func (a *ScopedDNSAdapter) commitSettings(ctx context.Context, p Plan, root string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s, err := a.snapshot(root)
	if err != nil {
		return err
	}
	if err := validateScopedSettingsSnapshot(s, p.DNS, p.SuspendDNS); err != nil {
		return err
	}
	// Recheck all settings before writing any, then each compare-and-swap
	// rechecks under the DNS manager lock. Partial writes use the SAME snapshot.
	current, err := a.reviewSettings(s.settingsScope(), p.DNS, p.SuspendDNS)
	if err != nil || !reflect.DeepEqual(current, s.Settings) {
		return dnscontrol.ErrServiceDNSChanged
	}
	for _, receipt := range s.Settings {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := a.DNS.CommitServiceSelection(receipt.Review); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func validateScopedSettingsSnapshot(s scopedDNSSnapshot, next *ScopedDNSPlan, suspend bool) error {
	scope := s.settingsScope()
	targets := scopedDNSSettingsTargets(scope, next, suspend)
	if len(targets) != len(s.Settings) {
		return ErrReviewChanged
	}
	for _, receipt := range s.Settings {
		r := receipt.Review
		target, exists := targets[r.ServiceID]
		if !exists || target != r.Target || receipt != r.Receipt() {
			return ErrReviewChanged
		}
		if scope != nil && scope.DNS.Bindings[0].ServiceID == r.ServiceID && scope.DNS.Bindings[0].ProfileID != r.Applied {
			return ErrReviewChanged
		}
		delete(targets, r.ServiceID)
	}
	return nil
}
