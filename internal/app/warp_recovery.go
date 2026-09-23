package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/warp"
)

// strictHandshakeFailure does not accept a joined cleanup error as permission
// for enrollment. A failed cleanup is a recovery barrier, not an offline node.
func strictHandshakeFailure(err error) bool {
	for err != nil {
		if _, ok := err.(dataplane.WARPHandshakeError); ok {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// Runs under existing exclusive application admission (HTTP or reconciler).
// Repair existing credentials first. Re-enrollment is explicit, budgeted and
// permitted only after exact transport exhaustion and a healthy control path.
func (a *App) processWarpHealth(ctx context.Context, items []warp.HealthEvidence) (warp.HealthDecision, error) {
	if a.Warp == nil {
		return warp.HealthDecision{}, errors.New("WARP manager unavailable")
	}
	blocked := func(reason string) (warp.HealthDecision, error) {
		s := a.Warp.Health()
		s.Eligible = false
		s.Reason = reason
		return warp.HealthDecision{HealthStatus: s}, nil
	}
	if a.Store == nil {
		return blocked("configuration-store-unavailable")
	}
	cfg := a.Store.Get()
	if cfg.ServiceControl.Stopped || cfg.ServiceControl.EffectiveMode() == "manual" {
		return blocked("global-manual-or-stopped")
	}
	// The old implementation checked Safe Mode only AFTER creating an account.
	if cfg.SafeMode {
		return blocked("safe-mode-blocked-recovery")
	}
	if err := ctx.Err(); err != nil {
		return warp.HealthDecision{}, err
	}
	decision, err := a.Warp.ObserveHealth(items)
	if err != nil || !decision.ShouldGenerate {
		return decision, err
	}
	decision.ShouldGenerate = false
	if a.Store.Dirty() || len(a.stagedEngineConfigRefs()) > 0 {
		return blocked("unsaved-draft-blocked-recovery")
	}
	if a.EngineConfigs == nil || a.Dataplane == nil || !a.Dataplane.CanaryCapable("warp-wg") {
		return blocked("isolated-canary-unavailable")
	}
	current, err := a.EngineConfigs.ReadExpert("warp-wg", "main")
	if err != nil || current.Source != "live" || current.Content == "" {
		return blocked("no-current-live-warp-profile")
	}
	profile, err := a.freshNetworkProfile(ctx)
	if err != nil || profile == "" {
		return blocked("recovery-network-unconfirmed")
	}
	if len(decision.State.LastFailedServices) == 0 {
		return blocked("no-failed-service")
	}
	serviceID := decision.State.LastFailedServices[0]
	if svc, ok := cfg.AppliedServices[serviceID]; !ok || !svc.Enabled || selectedRoute(svc) != "warp-wg" {
		return blocked("service-no-longer-on-warp")
	}
	plan, err := a.tunnelProbePlan("warp-wg", serviceID, false)
	if err != nil {
		return blocked("service-probe-unavailable")
	}
	// A manual request cancels the reconciler; all fresh network reads also fence
	// WAN changes. Policy comparison prevents stale permission at the last moment.
	stillAllowed := func(c context.Context) error {
		if err := c.Err(); err != nil {
			return err
		}
		now := a.Store.Get()
		if now.Revision != cfg.Revision || now.SafeMode || now.ServiceControl.Stopped || now.ServiceControl.EffectiveMode() == "manual" || a.Warp.Health().Policy != decision.Policy {
			return dataplane.ErrReviewChanged
		}
		p, e := a.freshNetworkProfile(c)
		if e != nil || p != profile {
			return dataplane.ErrNetworkChanged
		}
		return nil
	}
	ctx = dataplane.WithReviewGuard(ctx, stillAllowed)
	probeErr := a.Dataplane.ProbeCandidate(ctx, plan, "warp-wg")
	if err := stillAllowed(ctx); err != nil {
		return blocked("recovery-network-or-policy-changed")
	}
	repair := probeErr == nil
	var undo func() error
	if repair {
		// Same key, same account, same endpoint data. The ordinary canary may select
		// another allowed WARP UDP port; nothing is applied just by staging.
		_, undo, err = a.EngineConfigs.StagePrivateWithRollback([]engineconfig.StageItem{{EngineID: "warp-wg", FileID: "main", Content: current.Content}})
		if err != nil {
			return decision, errors.New("cannot stage current WARP for repair")
		}
		_ = a.Warp.RecordRecovery("candidate-repair-staged")
	} else {
		if !strictHandshakeFailure(probeErr) {
			_ = a.Warp.RecordRecovery("service-failed-account-kept")
			return blocked("service-failed-account-kept")
		}
		if !decision.Policy.AllowAccountRefresh {
			_ = a.Warp.RecordRecovery("transport-exhausted-refresh-disabled")
			return blocked("transport-exhausted-refresh-disabled")
		}
		controlCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		control := a.Warp.CheckConnectivity(controlCtx)
		cancel()
		if !control.Registration.Ready {
			_ = a.Warp.RecordRecovery("control-path-unavailable")
			return blocked("control-path-unavailable")
		}
		if err := stillAllowed(ctx); err != nil {
			return blocked("recovery-network-or-policy-changed")
		}
		if _, err = a.Warp.GenerateAutomatic(ctx, decision.Policy); err != nil {
			return blocked("registration-pending-or-failed")
		}
	}
	decision.Reason = "candidate-staged-awaiting-transactional-apply"
	if !decision.Policy.AutoApplyCandidate {
		return decision, nil
	}
	if err := stillAllowed(ctx); err != nil {
		// Do not run a failed operation's stale undo against newer state: the
		// StagePrivate rollback uses CAS and refuses conflicting generations.
		if undo != nil {
			_ = undo()
		}
		return decision, err
	}
	transaction, err := a.buildDataplanePlanForScope(cfg, a.routeOptionsSnapshot(), changeScopeEngine, "warp-wg")
	if err != nil || !transaction.Ready || transaction.Noop {
		decision.Reason = "candidate-staged-transaction-blocked"
		return decision, nil
	}
	binding, err := a.bindApplyReview(ctx, cfg, transaction, changeScopeEngine, "warp-wg")
	if err != nil {
		return decision, err
	}
	guard := func(c context.Context) error {
		if err := stillAllowed(c); err != nil {
			return err
		}
		return binding.guard(a, c)
	}
	ctx = dataplane.WithReviewGuard(ctx, guard)
	execution, err := a.applyDataplane(ctx, transaction, nil)
	if err != nil {
		_ = a.Warp.RecordActivation(false, "transaction-failed")
		return decision, fmt.Errorf("WARP recovery transaction failed (%s); candidate and rollback state retained", execution.State)
	}
	if err := a.Warp.RecordActivation(true, ""); err != nil {
		return decision, err
	}
	if repair {
		decision.Reason = "candidate-repair-activated"
		_ = a.Warp.RecordRecovery(decision.Reason)
	} else {
		decision.Reason = "fresh-profile-activated"
	}
	return decision, nil
}
