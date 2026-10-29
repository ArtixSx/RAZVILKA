package app

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"reflect"
)

type nfqRecoveryStopReview struct {
	owner    *App
	cfg      config.Config
	plan     dataplane.Plan
	recovery dataplane.Recovery
	catalog  string
}

func (a *App) reviewNFQRecoveryStop(ctx context.Context, cfg config.Config) (*nfqRecoveryStopReview, error) {
	if a == nil || a.Dataplane == nil || !cfg.SafeMode || cfg.ServiceControl.Stopped || a.PendingSelfUpdateRecovery() || a.PendingComponentRecovery() {
		return nil, errDataplaneBootRecovery
	}
	status, err := a.Dataplane.Status()
	if err != nil || status.CommittedPlan == nil || status.Recovery == nil {
		return nil, errDataplaneBootRecovery
	}
	p, r := *status.CommittedPlan, *status.Recovery
	if status.Execution == nil || status.Execution.PlanID != p.PlanID || status.Execution.State != "committed" || status.Execution.Digest != p.Digest {
		return nil, errDataplaneBootRecovery
	}
	if err := a.Dataplane.CheckExecutionRecovery(ctx); err != nil {
		return nil, err
	}
	if r.PlanID != p.PlanID || r.State != "degraded" || r.Guarded || r.FailureCount != 1 || p.Revision != cfg.AppliedRevision {
		return nil, errDataplaneBootRecovery
	}
	failed, settled := 0, 0
	for _, s := range r.Steps {
		switch {
		case s.Adapter == "dns-scoped" && s.State == "dns-redirects-released":
		case s.Adapter == "nfqws2" && s.State == "failed" && s.Detail == "active NFQWS2 NFQUEUE rules were not confirmed: post-hook-unreachable":
			failed++
		case s.Adapter == "nfqws2" && s.State == "safe-mode-deactivated" && s.Detail == "":
			settled++
		default:
			return nil, errDataplaneBootRecovery
		}
	}
	if failed != 1 || settled != 1 {
		return nil, errDataplaneBootRecovery
	}
	review := &nfqRecoveryStopReview{owner: a, cfg: cfg, plan: p, recovery: r, catalog: applyReviewHash(a.catalogSnapshot())}
	if err := review.check(ctx, true); err != nil {
		return nil, err
	}
	return review, nil
}
func (r *nfqRecoveryStopReview) check(ctx context.Context, configuration bool) error {
	if ctx == nil || ctx.Err() != nil || r == nil || r.owner == nil {
		return errDataplaneBootRecovery
	}
	a := r.owner
	if configuration && !reflect.DeepEqual(a.Store.Get(), r.cfg) || applyReviewHash(a.catalogSnapshot()) != r.catalog {
		return dataplane.ErrReviewChanged
	}
	s, e := a.Dataplane.Status()
	if e != nil || s.CommittedPlan == nil || s.Recovery == nil || !reflect.DeepEqual(*s.CommittedPlan, r.plan) || !reflect.DeepEqual(*s.Recovery, r.recovery) {
		return errDataplaneBootRecovery
	}
	if a.PendingSelfUpdateRecovery() || a.PendingComponentRecovery() {
		return errDataplaneBootRecovery
	}
	return a.Dataplane.ObserveNFQWS2RecoveryStopInactive(ctx, r.plan)
}

// ObservePendingNFQRecoveryStop preserves the exact failed-boot proof across a
// panel restart. It grants no restart, Stop, flag clear or journal mutation.
// Unknown histories fall through to ordinary Manager recovery and cleanup.
func (a *App) ObservePendingNFQRecoveryStop(ctx context.Context) (dataplane.Recovery, bool, error) {
	if a == nil || a.Store == nil || !a.Store.Get().SafeMode {
		return dataplane.Recovery{}, false, nil
	}
	r, e := a.reviewNFQRecoveryStop(ctx, a.Store.Get())
	if e != nil {
		return dataplane.Recovery{}, false, e
	}
	return r.recovery, true, errDataplaneBootRecovery
}

// Legacy no-record flags retain their existing path. Unknown recovery records
// cannot borrow that path to clear a failed boot fence through explicit Stop.
func (a *App) recoveryStopReviewRequired(ctx context.Context, cfg config.Config) bool {
	s, e := a.Dataplane.Status()
	if e != nil {
		return true
	}
	if s.Recovery == nil {
		return false
	}
	r, p, x := s.Recovery, s.CommittedPlan, s.Execution
	return !(r.State == "recovered" && !r.Guarded && r.FailureCount == 0 && p != nil && x != nil && r.PlanID == p.PlanID && p.Revision == cfg.AppliedRevision && x.PlanID == p.PlanID && x.Digest == p.Digest && x.State == "committed" && a.Dataplane.CheckExecutionRecovery(ctx) == nil)
}
