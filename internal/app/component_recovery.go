package app

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

var errComponentRecovery = errors.New("component update requires reviewed recovery")

type componentAdmissionKey struct{}
type componentAdmission struct {
	inspect, stop          bool
	transaction, component string
}

// InitializeComponentRecoveryGate runs before collectors, HTTP and recovery.
// Journal reads are bounded and do not take the component manager's mutex.
func (a *App) InitializeComponentRecoveryGate() error {
	return a.Operations.SetGuard(func(ctx context.Context) error {
		if a.Dataplane != nil {
			if err := CheckNFQWS2HookRecovery(a.Dataplane.StateRoot); err != nil {
				return err
			}
		}
		if err := a.selfUpdateFileGuard(ctx); err != nil {
			return err
		}
		if a.Components == nil {
			return nil
		}
		state, pending, err := a.Components.PendingManagedUpdate()
		if !pending && err == nil {
			return nil
		}
		if scope, ok := ctx.Value(componentAdmissionKey{}).(componentAdmission); ok && (scope.inspect || scope.stop) {
			return nil // Does not bypass private/network recovery fences.
		}
		if scope, ok := ctx.Value(componentAdmissionKey{}).(componentAdmission); ok && err == nil && pending && scope.transaction != "" && scope.transaction == state.TransactionID && scope.component == state.Component {
			return nil // Exact repair only; the Manager checks again under its durable lock.
		}
		return errComponentRecovery
	})
}

// PendingComponentRecovery is read-only and fail-closed on damaged records.
func (a *App) PendingComponentRecovery() bool {
	if a.Components == nil {
		return false
	}
	_, pending, err := a.Components.PendingManagedUpdate()
	return pending || err != nil
}

func componentStopContext(ctx context.Context, action string) context.Context {
	if action != "stop" {
		return ctx
	}
	return context.WithValue(ctx, componentAdmissionKey{}, componentAdmission{stop: true})
}

func (a *App) componentRecoveryStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodPost {
		a.componentRecoveryAction(w, r)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Security == nil || !a.Security.Authenticated(r) {
		http.Error(w, "administrator login is required", http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, componentAdmissionKey{}, componentAdmission{inspect: true})
	release, err := a.Operations.Enter(ctx)
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer func() {
		if release != nil {
			release()
		}
	}()
	if a.Components == nil {
		http.Error(w, "component manager unavailable", http.StatusServiceUnavailable)
		return
	}
	state, pending, err := a.Components.PendingManagedUpdate()
	if err == nil && pending && state.SchemaVersion == components.ManagedNFQWSJournalSchema && state.Component == "nfqws2" {
		// Ordinary journal reads may overlap other readers. Only matching
		// managed recovery capabilities need an original exclusive control
		// review. Re-read after acquiring it; never promote the earlier DTO.
		release()
		release = nil
		ctx, release, err = a.Operations.ExclusiveContext(ctx)
		if err != nil {
			a.writeOperationFailure(w, err)
			return
		}
		state, pending, err = a.Components.PendingManagedUpdate()
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"recovery_required": true, "code": "COMPONENT_JOURNAL_UNAVAILABLE", "error": "Журнал обновления не читается. Автоматические изменения приостановлены; сохраните журнал и резервную копию."})
		return
	}
	var revision uint64
	if a.Store != nil {
		revision = a.Store.Get().Revision
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_required": pending, "transaction": state, "revision": revision, "working_routes_changed": false, "capabilities": a.componentRecoveryCapabilities(ctx, state, pending), "installed_idle_accepted": !pending && state.InstalledIdleAccepted()})
}

// Callbacks are trusted application dependencies, never decoded from a request.
// The zero value uses native inspection. Tests may replace observations only.
type componentRecoveryChecks struct {
	quiescence func(context.Context) error
	live       func(context.Context, string) error
	inactive   func(context.Context, string) error
}

func (a *App) componentRecoveryAction(w http.ResponseWriter, r *http.Request) {
	if a.Security == nil || !a.Security.Authenticated(r) {
		http.Error(w, "administrator login is required", http.StatusUnauthorized)
		return
	}
	var in struct {
		TransactionID           string  `json:"transaction_id"`
		Component               string  `json:"component"`
		Action                  string  `json:"action"`
		ExpectedRevision        *uint64 `json:"expected_revision"`
		Confirm                 string  `json:"confirm"`
		AllowUnknownRollback    bool    `json:"allow_unknown_rollback"`
		ExternalRepairConfirmed bool    `json:"external_repair_confirmed"`
	}
	if !decodeServiceControl(w, r, &in) {
		return
	}
	if in.TransactionID == "" || !components.ManagedUpdateSupported(in.Component) || in.ExpectedRevision == nil || in.Confirm != "REPAIR_COMPONENT_TRANSACTION" || (in.Action != "resume" && in.Action != "accept-live" && in.Action != "accept-installed-idle" && in.Action != "rollback" && in.Action != "verify-rollback" && in.Action != "abandon-prepared") || in.AllowUnknownRollback && in.Action != "rollback" || in.ExternalRepairConfirmed && in.Action != "verify-rollback" {
		http.Error(w, "invalid matching component recovery request", http.StatusBadRequest)
		return
	}
	if a.Components == nil || a.Store == nil {
		http.Error(w, "component recovery unavailable", http.StatusServiceUnavailable)
		return
	}
	if a.SelfUpdate != nil && a.SelfUpdate.InstallationLocked() {
		a.writeOperationFailure(w, errComponentRecovery)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Minute)
	defer cancel()
	observed, pendingObserved, err := a.Components.PendingManagedUpdate()
	if err != nil {
		a.writeOperationFailure(w, errComponentRecovery)
		return
	}
	if observed.TransactionID != in.TransactionID || observed.Component != in.Component {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "COMPONENT_TRANSACTION_CHANGED", "error": "component recovery does not match the reviewed transaction"})
		return
	}
	if observed.SchemaVersion == components.NFQWSInitialInstallSchema {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "NFQWS_INITIAL_INSTALL_REVIEW_REQUIRED", "error": "Первичная установка NFQWS2 требует проверки сохранённого журнала; автоматический повтор и обычный откат пакета недоступны."})
		return
	}
	managedBundle := observed.SchemaVersion == components.ManagedNFQWSJournalSchema && observed.Component == "nfqws2"
	if managedBundle && (!slices.Contains(managedNFQRecoveryActions(observed, pendingObserved), in.Action) || in.AllowUnknownRollback || in.ExternalRepairConfirmed) || !managedBundle && in.Action == "resume" {
		http.Error(w, "invalid matching component recovery action", http.StatusBadRequest)
		return
	}
	ctx = context.WithValue(ctx, componentAdmissionKey{}, componentAdmission{transaction: in.TransactionID, component: in.Component})
	ctx, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer release()
	defer a.wakePanelSnapshot()
	if managedBundle {
		a.recoverManagedNFQBundle(w, ctx, observed, in.Action, *in.ExpectedRevision)
		return
	}
	guard, err := a.componentUpdateGuard(ctx)
	if err == nil && in.Action == "rollback" && pendingObserved {
		guard = a.nfqwsPackageUpdateGuard(in.Component, guard)
		err = guard(ctx)
	}
	if err == nil && a.Store.Get().Revision != *in.ExpectedRevision {
		err = components.ErrRecoveryAuthority
	}
	if err != nil {
		if writeNFQWSPackageMutationFailure(w, err) {
			return
		}
		writeJSON(w, http.StatusConflict, map[string]any{"code": "COMPONENT_AUTHORITY_CHANGED", "error": err.Error()})
		return
	}
	cfg := a.Store.Get()
	ctx = dataplane.WithReviewGuard(ctx, guard)
	// Settling the package journal and clearing the scheduler checkpoint are
	// separate durable writes. Retry only the latter after a proven settlement.
	state, pending, readErr := a.Components.PendingManagedUpdate()
	a.autonomy.mu.Lock()
	maintenance := a.autonomy.doc.Maintenance["components"] == componentPendingPrefix+in.Component
	a.autonomy.mu.Unlock()
	settledAction := state.Phase == components.UpdateAccepted && in.Action == "accept-live" || state.Phase == components.UpdateAcceptedIdle && in.Action == "accept-installed-idle" || state.Phase == components.UpdateRolledBack && (in.Action == "rollback" || in.Action == "verify-rollback") || state.Phase == components.UpdateAbandoned && in.Action == "abandon-prepared"
	if readErr == nil && !pending && state.TransactionID == in.TransactionID && state.Component == in.Component && settledAction {
		operationPending, operationErr := a.componentSettlementNeeded(state)
		if operationErr != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"code": "COMPONENT_CHECKPOINT_PENDING", "error": operationErr.Error()})
			return
		}
		if !maintenance && !operationPending {
			writeJSON(w, http.StatusConflict, map[string]any{"code": "COMPONENT_TRANSACTION_SETTLED", "error": "component transaction already settled"})
			return
		}
		if err := guard(ctx); err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"code": "COMPONENT_AUTHORITY_CHANGED", "error": err.Error()})
			return
		}
		if err := a.settleComponentRecovery(ctx, in.TransactionID, in.Component, guard); err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"code": "COMPONENT_CHECKPOINT_PENDING", "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"recovery_required": false, "checkpoint_settled": true, "live_accepted": false})
		return
	}
	quiescence := a.componentRecoveryChecks.quiescence
	if quiescence == nil {
		quiescence = func(c context.Context) error { return a.Components.Quiescence(c, in.TransactionID, in.Component) }
	}
	live := a.componentRecoveryChecks.live
	if live == nil {
		live = a.checkComponentLive
	}
	result, err := a.Components.RecoverManagedUpdate(ctx, components.ManagedRecoveryRequest{
		TransactionID: in.TransactionID, Component: in.Component, Action: in.Action,
		AllowUnknownRollback: in.AllowUnknownRollback, ExternalRepairConfirmed: in.ExternalRepairConfirmed,
		SafeMode: cfg.SafeMode, Stopped: cfg.ServiceControl.Stopped, QuiescenceCheck: quiescence,
		InactivityCheck: func(c context.Context) error {
			if err := guard(c); err != nil {
				return err
			}
			if err := a.checkComponentInactive(c, in.Component); err != nil {
				return err
			}
			return guard(c)
		},
	}, guard, func(c context.Context) error {
		if err := guard(c); err != nil {
			return err
		}
		// A rollback of a dormant component verifies inactivity, without claiming
		// that a service is live. accept-live always requires actual runtime.
		if in.Action != "accept-live" && !a.managedUpdateInUse(in.Component) {
			return a.checkComponentInactive(c, in.Component)
		}
		return live(c, in.Component)
	})
	if err == nil {
		err = a.settleComponentRecovery(ctx, in.TransactionID, in.Component, guard)
	}
	if err != nil {
		if writeNFQWSPackageMutationFailure(w, err) {
			return
		}
		writeJSON(w, http.StatusConflict, map[string]any{"code": "COMPONENT_RECOVERY_UNCONFIRMED", "error": err.Error(), "result": result, "recovery_required": a.PendingComponentRecovery()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": result, "recovery_required": false, "live_accepted": in.Action == "accept-live", "installed_idle_accepted": result.InstalledIdleAccepted})
}

// Recheck actual authority after preparation and before every package command.
func (a *App) componentUpdateGuard(ctx context.Context) (func(context.Context) error, error) {
	if a.Store == nil {
		return nil, components.NoMutation(components.ErrRecoveryAuthority)
	}
	cfg := a.Store.Get()
	guard := func(c context.Context) error {
		if err := c.Err(); err != nil {
			return err
		}
		current := a.Store.Get()
		if current.Revision != cfg.Revision || current.SafeMode || current.ServiceControl.Stopped {
			return components.ErrRecoveryAuthority
		}
		return nil
	}
	return guard, guard(ctx)
}

func (a *App) recordComponentAwaitingLive(id string) {
	_ = a.Components.RecordOperation(id, "update", "running", "Пакет установлен и проверен отдельно. Рабочий процесс ещё не подтвердил новую версию; прежняя версия сохранена для отката.")
	a.wakePanelSnapshot()
}

func (a *App) recordComponentAwaitingRollback(id string) {
	_ = a.Components.RecordOperation(id, "update", "running", "Пакет и настройки возвращены к прежней версии. Независимое подтверждение рабочего процесса после отката ещё требуется.")
	a.wakePanelSnapshot()
}
