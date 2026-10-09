package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

// Manual choice is metadata only. The actual source owns compatibility and
// atomic publication; no API body supplies runtime paths, evidence or health.
func (a *App) selectManagedStrategyManual(w http.ResponseWriter, r *http.Request, serviceID, protocol, family, candidateID string) {
	if a == nil || a.Store == nil || a.Components == nil || a.SelfUpdateFiles == nil || a.StrategyLab == nil {
		writeManagedManualSelectionError(w, http.StatusServiceUnavailable, "MANAGED_NFQWS_SOURCE_UNAVAILABLE")
		return
	}
	known := false
	for _, service := range a.catalogSnapshot().Services {
		known = known || service.ID == serviceID
	}
	if !known || candidateID == "" || protocol != "tcp" && protocol != "quic" || family != "ipv4" && family != "ipv6" {
		http.Error(w, "invalid manual selection target", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	ctx, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer release()
	if a.managedNFQListPending() || a.strategyCompatibilityPending() {
		a.writeOperationFailure(w, operationgate.ErrBusy)
		return
	}
	control, err := a.managedNFQControl(ctx)
	if err != nil {
		writeManagedManualSelectionError(w, http.StatusConflict, "MANAGED_NFQWS_MANUAL_SELECTION_REFUSED")
		return
	}
	defer a.closeUnretainedManagedNFQControl(control)
	if err := control.Current(ctx); err != nil {
		writeManagedManualSelectionError(w, http.StatusConflict, "MANAGED_NFQWS_MANUAL_SELECTION_REFUSED")
		return
	}
	runtime, err := a.Components.AcquireCurrentManagedNFQWSRuntime(ctx)
	if err != nil {
		writeManagedManualSelectionError(w, http.StatusServiceUnavailable, "MANAGED_NFQWS_SOURCE_UNAVAILABLE")
		return
	}
	selection, selectionErr := a.StrategyLab.SelectManual(ctx, serviceID, protocol, family, candidateID, runtime)
	closingErr := errors.Join(control.Current(ctx), runtime.Check(ctx), runtime.Close())
	if err := errors.Join(selectionErr, closingErr); err != nil {
		writeManagedManualSelectionError(w, http.StatusConflict, "MANAGED_NFQWS_MANUAL_SELECTION_REFUSED")
		return
	}
	if selection.Mode != strategylab.ModeManual || !selection.Frozen || selection.Healthy || selection.Confidence != 0 || selection.LastHealthyAt != "" {
		writeManagedManualSelectionError(w, http.StatusConflict, "MANAGED_NFQWS_MANUAL_SELECTION_REFUSED")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, selection)
}

func writeManagedManualSelectionError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]any{"ok": false, "code": code, "error": "Ручной выбор не подтверждён. Проверьте совместимость установленной стратегии и обновите данные лаборатории.", "live_applied": false})
}
