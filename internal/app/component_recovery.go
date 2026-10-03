package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/ArtixSx/razvilka/internal/components"
)

var errComponentRecovery = errors.New("component update requires reviewed recovery")

type componentAdmissionKey struct{}
type componentAdmission struct{ inspect, stop bool }

// InitializeComponentRecoveryGate runs before collectors, HTTP and recovery.
// Journal reads are bounded and do not take the component manager's mutex.
func (a *App) InitializeComponentRecoveryGate() error {
	return a.Operations.SetGuard(func(ctx context.Context) error {
		if a.Components == nil {
			return nil
		}
		_, pending, err := a.Components.PendingManagedUpdate()
		if !pending && err == nil {
			return nil
		}
		if scope, ok := ctx.Value(componentAdmissionKey{}).(componentAdmission); ok && (scope.inspect || scope.stop) {
			return nil // Does not bypass private/network recovery fences.
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
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Security == nil || !a.Security.Authenticated(r) {
		http.Error(w, "administrator login is required", http.StatusUnauthorized)
		return
	}
	ctx := context.WithValue(r.Context(), componentAdmissionKey{}, componentAdmission{inspect: true})
	release, err := a.Operations.Enter(ctx)
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer release()
	if a.Components == nil {
		http.Error(w, "component manager unavailable", http.StatusServiceUnavailable)
		return
	}
	state, pending, err := a.Components.PendingManagedUpdate()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"recovery_required": true, "code": "COMPONENT_JOURNAL_UNAVAILABLE", "error": "Журнал обновления не читается. Автоматические изменения приостановлены; сохраните журнал и резервную копию."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_required": pending, "transaction": state, "working_routes_changed": false})
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
	_ = a.Components.RecordOperation(id, "update", "pending", "Пакет установлен и проверен отдельно. Рабочий процесс ещё не подтвердил новую версию; прежняя версия сохранена для отката.")
	a.wakePanelSnapshot()
}
