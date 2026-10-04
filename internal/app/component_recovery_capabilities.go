package app

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/components"
)

// available_actions are matching requests the server can admit, not a promise
// of acceptance. Live checks and all authority/quiescence are repeated in POST.
func (a *App) componentRecoveryCapabilities(ctx context.Context, state components.ManagedUpdateState, pending bool) map[string]any {
	actions := []string{}
	result := map[string]any{"supported_actions": []string{"accept-live", "accept-installed-idle", "rollback", "verify-rollback", "abandon-prepared"}, "available_actions": actions, "installed_idle_accepted": state.Phase == components.UpdateAcceptedIdle, "live_proof_required": true, "quiescence_confirmed": false, "inactivity_confirmed": false}
	if !pending {
		return result
	}
	guard, err := a.componentUpdateGuard(ctx)
	if err != nil {
		return result
	}
	quiescence := a.componentRecoveryChecks.quiescence
	if quiescence == nil {
		quiescence = func(c context.Context) error { return a.Components.Quiescence(c, state.TransactionID, state.Component) }
	}
	quiet := quiescence(ctx) == nil
	inactive := false
	if state.Phase == components.UpdateAwaitingLive && quiet {
		inactive = a.checkComponentInactive(ctx, state.Component) == nil
	}
	if guard(ctx) != nil {
		return result
	}
	result["quiescence_confirmed"], result["inactivity_confirmed"] = quiet, inactive
	switch state.Phase {
	case components.UpdatePrepared:
		actions = append(actions, "abandon-prepared")
	case components.UpdateAwaitingLive:
		actions = append(actions, "accept-live", "rollback")
		if quiet && inactive {
			actions = append(actions, "accept-installed-idle")
		}
	case components.UpdateStarted:
		if quiet {
			actions = append(actions, "rollback")
		}
	case components.UpdateRollbackStarted:
		if quiet {
			actions = append(actions, "verify-rollback")
		}
	case components.UpdateAwaitingRollback:
		actions = append(actions, "verify-rollback")
	case components.UpdateInstalled, components.UpdateRestoreBefore, components.UpdateRollbackReady, components.UpdateRollbackInstalled, components.UpdateRestoreAfter:
		actions = append(actions, "rollback")
	}
	result["available_actions"] = actions
	return result
}
