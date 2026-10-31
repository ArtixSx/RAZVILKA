package app

import (
	"context"
	"net/http"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
)

const hevRecoveryPath = "/api/v1/components/hev-socks5-tunnel/recovery"

func (a *App) hevRecovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Security == nil || !a.Security.Authenticated(r) {
		http.Error(w, "administrator login is required", http.StatusUnauthorized)
		return
	}
	if a.Components == nil || a.Store == nil {
		http.Error(w, "component recovery unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	owner := a.Components
	if r.Method == http.MethodGet {
		ctx = context.WithValue(ctx, componentAdmissionKey{}, componentAdmission{inspect: true})
		release, err := a.Operations.Enter(ctx)
		if err != nil {
			a.writeOperationFailure(w, err)
			return
		}
		defer release()
		review, err := owner.InspectHEVReleaseRecovery(ctx)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"recovery_required": true, "repair_available": false, "code": "HEV_JOURNAL_UNAVAILABLE"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"recovery_required": review.Pending, "review": review, "revision": a.Store.Get().Revision, "repair_available": review.Pending && review.Identity != "", "live_applied": false})
		return
	}
	var input struct {
		Identity string  `json:"expected_identity"`
		Revision *uint64 `json:"expected_revision"`
	}
	if !decodeServiceControl(w, r, &input) {
		return
	}
	if len(input.Identity) != 64 || input.Revision == nil {
		http.Error(w, "exact journal identity and settings revision required", http.StatusBadRequest)
		return
	}
	ctx = context.WithValue(ctx, componentAdmissionKey{}, componentAdmission{hevRepair: owner})
	ctx, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer release()
	defer a.wakePanelSnapshot()
	store, cfg := a.Store, a.Store.Get()
	if cfg.Revision != *input.Revision {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "HEV_REVIEW_CHANGED", "not_started": true})
		return
	}
	if err := store.WithResourceExclusionObservation(ctx, cfg, func(config.EffectiveExclusionSet) error { return nil }); err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	// Recovery only replays the existing, matching original journal and targets.
	// It never downloads, creates a new transaction, starts a process or routes.
	outcome, err := owner.RecoverHEVReleaseReviewed(ctx, input.Identity)
	if err == nil && (a.Components != owner || a.Store != store) {
		err = components.ErrRecoveryAuthority
	}
	if err == nil {
		err = store.WithResourceExclusionObservation(ctx, cfg, func(config.EffectiveExclusionSet) error { return nil })
	}
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "HEV_RECOVERY_UNCONFIRMED", "recovery_required": true, "outcome": outcome})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_required": false, "outcome": outcome, "live_applied": false, "restart_required": true})
}
