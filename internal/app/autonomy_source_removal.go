package app

import (
	"context"
	"slices"

	"github.com/ArtixSx/razvilka/internal/autonomy"
)

// Caller holds exclusive application admission and has checked the feed CAS.
// Withdraw permission BEFORE removing the subscription: an interrupted delete
// may leave a saved feed, but must never recreate one the user removed. The
// two stores need no widening rollback; the retained restriction is reported.
func (a *App) withdrawAutonomySource(ctx context.Context, id string) (bool, bool, error) {
	if err := a.loadAutonomy(ctx); err != nil {
		return false, false, err
	}
	if err := a.autonomyDiskCurrent(ctx); err != nil {
		return false, false, err
	}
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	p := autonomy.Clone(a.autonomy.doc.Policy)
	if !slices.Contains(p.SourceIDs, id) {
		return false, false, nil
	}
	p.SourceIDs = slices.DeleteFunc(p.SourceIDs, func(value string) bool { return value == id })
	p.Revision++
	paused := p.Enabled && len(p.SourceIDs) == 0 && len(p.PreferredRoutes) == 0
	if paused {
		p.Enabled = false
	}
	if err := autonomy.Validate(p); err != nil {
		return false, false, err
	}
	old := a.autonomy.doc.Policy
	a.autonomy.doc.Policy = p
	if err := a.persistAutonomyLocked(ctx); err != nil {
		a.autonomy.doc.Policy = old // persist failure fences further automation.
		return false, false, err
	}
	a.autonomy.refillState.SourceID = ""
	a.autonomy.refillState.State = "source-removed"
	a.autonomy.maintenanceMessage = "Удалённый источник исключён из автоподбора. Сохранённые подключения и рабочие маршруты не изменены."
	if paused {
		a.autonomy.maintenanceMessage += " Автопилот на паузе: разрешённых источников и обходов больше нет."
	}
	return true, paused, nil
}
