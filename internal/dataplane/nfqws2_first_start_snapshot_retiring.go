package dataplane

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
	"slices"
)

// Manager supplies the prior committed plan under its transaction lock. A
// retiring first-start instance is observed against its existing recipe; the
// empty Stop target is never compiled into a new runnable configuration.
func (a *NFQWS2Adapter) snapshotRetiring(ctx context.Context, plan, previous Plan, root string) error {
	// Managed execution is bound to the new operation and must keep that plan.
	if _, present, _ := nfqws2ActiveExecutionFor(ctx, a, plan, root); present {
		return a.Snapshot(ctx, plan, root)
	}
	lease, err := a.readLease()
	if err != nil {
		return preflightRefusalError{err}
	}
	if lease == nil || lease.FirstStart == nil {
		return a.Snapshot(ctx, plan, root)
	}
	if plan.SchemaVersion != SchemaVersion || previous.SchemaVersion != SchemaVersion || previous.State != "committed" ||
		!validPlanID(previous.PlanID) || !validPlanDigest(previous.Digest) || !slices.Contains(plan.RetiringAdapters, a.ID()) ||
		slices.Contains(plan.Adapters, a.ID()) || !slices.Contains(previous.Adapters, a.ID()) {
		return preflightRefusalError{ErrReviewChanged}
	}
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) == a.ID() {
			return preflightRefusalError{ErrReviewChanged}
		}
	}
	for _, file := range append([]string{"main"}, nfqws2ListFileIDs[:]...) {
		if planUsesEngineDraft(plan, a.ID(), file) {
			return preflightRefusalError{ErrReviewChanged}
		}
	}
	transaction := filepath.Join(filepath.Dir(filepath.Dir(a.StateRoot)), "transactions", previous.PlanID, a.ID())
	if lease.Transaction != transaction {
		return preflightRefusalError{ErrReviewChanged}
	}
	config, exists, err := nfqws2Read(a.ConfigPath)
	if err != nil || !exists {
		return preflightRefusalError{ErrReviewChanged}
	}
	expected, err := a.firstStartConfig(previous, config)
	if err != nil || !bytes.Equal(expected, config) {
		return preflightRefusalError{ErrReviewChanged}
	}
	if err := a.Snapshot(ctx, previous, root); err != nil {
		return err
	}
	// Snapshot repeats all original draft, scope, init, overlay and runtime
	// ownership checks. Bind its saved image to the same prior lease and bytes.
	snapshot, err := readNFQWS2Snapshot(root)
	if err != nil || !snapshot.FirstStart || !reflect.DeepEqual(snapshot.Lease, lease) || !bytes.Equal(snapshot.Config, config) {
		return preflightRefusalError{ErrReviewChanged}
	}
	return nil
}
