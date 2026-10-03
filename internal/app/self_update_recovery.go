package app

import (
	"context"
	"net/http"
	"time"

	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

func (a *App) selfUpdateFileAuthority(ctx context.Context, revision uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.Store == nil {
		return errSelfUpdateRecovery
	}
	cfg := a.Store.Get()
	if cfg.Revision != revision || cfg.SafeMode || cfg.ServiceControl.Stopped {
		return updatecheck.ErrReviewChanged
	}
	return nil
}

func (a *App) selfUpdateRecovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.Security == nil || !a.Security.Authenticated(r) {
		http.Error(w, "administrator login is required", http.StatusUnauthorized)
		return
	}
	if a.SelfUpdateFiles == nil {
		http.Error(w, "self update file recovery unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodGet {
		control := a.SelfUpdateFiles.controlView(r.Context())
		state, present, err := a.SelfUpdateFiles.Current()
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": "SELF_UPDATE_JOURNAL_UNAVAILABLE", "recovery_required": true, "control": control, "error": "Журнал обновления приложения не читается. Сохраните журнал и прежнюю версию для проверки."})
			return
		}
		var revision uint64
		if a.Store != nil {
			revision = a.Store.Get().Revision
		}
		// Inspection reads bounded journals only and remains available while
		// the installer owns admission. It never invokes the adapter or repairs.
		writeJSON(w, http.StatusOK, map[string]any{"recovery_required": a.PendingSelfUpdateRecovery(), "present": present, "transaction": state, "revision": revision, "control": control, "adapter_available": a.SelfUpdateFiles.Adapter != nil})
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var in struct {
		ID       string  `json:"transaction_id"`
		Action   string  `json:"action"`
		Revision *uint64 `json:"expected_revision"`
		Confirm  string  `json:"confirm"`
	}
	if !decodeSelfUpdate(w, r, &in) {
		return
	}
	if !selfUpdateID.MatchString(in.ID) || in.Revision == nil || in.Confirm != "REPAIR_SELF_UPDATE_TRANSACTION" || !selfUpdateFileAction(in.Action) {
		http.Error(w, "invalid matching self update recovery request", http.StatusBadRequest)
		return
	}
	// Repair cannot borrow a live installer's lease, or bypass independent
	// component/private/network fences. Once abandoned, the dynamic file/helper
	// fence can admit this exact ID without permanently locking out repair.
	if a.SelfUpdate != nil && a.SelfUpdate.InstallationLocked() {
		a.writeOperationFailure(w, errSelfUpdateRecovery)
		return
	}
	state, present, err := a.SelfUpdateFiles.Current()
	if err != nil {
		a.writeOperationFailure(w, errSelfUpdateRecovery)
		return
	}
	matching := present && state.ID == in.ID
	if !present && a.SelfUpdateFiles.Helper != nil {
		matching = a.SelfUpdateFiles.Helper.Snapshot().ID == in.ID
	}
	if !matching {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "SELF_UPDATE_TRANSACTION_CHANGED", "error": "self update recovery does not match the reviewed transaction"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Minute)
	defer cancel()
	ctx = context.WithValue(ctx, selfUpdateFileAdmissionKey{}, selfUpdateFileAdmission{id: in.ID})
	release, err := a.Operations.Exclusive(ctx)
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer release()
	defer a.wakePanelSnapshot()
	guard := func(c context.Context) error { return a.selfUpdateFileAuthority(c, *in.Revision) }
	if err = guard(ctx); err == nil {
		err = a.SelfUpdateFiles.Action(ctx, in.ID, in.Action, *in.Revision, guard)
	}
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "SELF_UPDATE_RECOVERY_UNCONFIRMED", "error": err.Error(), "recovery_required": a.PendingSelfUpdateRecovery()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_required": a.PendingSelfUpdateRecovery(), "live_accepted": in.Action == "accept-live", "rollback_accepted": in.Action == "accept-rollback"})
}

func selfUpdateFileAction(action string) bool {
	switch action {
	case "prepare", "install", "restore", "accept-live", "accept-rollback", "resolve-unknown", "stop-old-panel", "start-candidate-panel", "stop-candidate-panel", "start-rollback-panel":
		return true
	}
	return false
}
