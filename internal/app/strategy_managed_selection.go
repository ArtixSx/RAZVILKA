package app

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"net/http"
	"time"
)

func (a *App) selectManagedStrategyEvidence(w http.ResponseWriter, r *http.Request, serviceID, protocol, family, candidateID string, mode strategylab.AdaptiveMode, frozen bool) {
	if a.managedStrategyProbeRuntime() == nil {
		writeManagedStrategyProbeError(w, false)
		return
	}
	known := false
	for _, service := range a.catalogSnapshot().Services {
		known = known || service.ID == serviceID
	}
	if !known || protocol != "tcp" || family != "ipv4" {
		http.Error(w, "invalid managed selection scope", http.StatusBadRequest)
		return
	}
	if mode == "" {
		mode = strategylab.ModePreferred
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	ctx, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer release()
	selection, err := a.StrategyLab.SelectManaged(ctx, serviceID, protocol, family, candidateID, mode, frozen)
	if err != nil {
		writeManagedStrategyProbeError(w, false)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, selection)
}
