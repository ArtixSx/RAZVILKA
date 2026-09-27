package app

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

const panelAutonomyPath = "/api/v1/panel/autonomy"
const panelAutonomyLifetime = 2 * time.Minute

// PreparePanelAutonomy reads permissions after boot recovery, before workers
// can own admission for their first long check. It never starts automation or
// creates consent. A fenced recovery must not reload uncertain state.
func (a *App) PreparePanelAutonomy(ctx context.Context) error {
	release, err := a.Operations.Exclusive(ctx)
	if err != nil {
		return err
	}
	defer release()
	return a.loadAutonomy(ctx)
}

type panelAutonomyPublication struct {
	InstanceID string
	Revision   uint64
	ObservedAt time.Time
	Data       json.RawMessage
}

type panelAutonomyResponse struct {
	Schema        int             `json:"schema"`
	InstanceID    string          `json:"instance_id"`
	Revision      uint64          `json:"revision"`
	ObservedAt    *time.Time      `json:"observed_at"`
	DataAgeMS     int64           `json:"data_age_ms"`
	MaxAgeSeconds int64           `json:"max_age_seconds"`
	State         string          `json:"state"`
	Dataplane     string          `json:"dataplane"`
	Data          json.RawMessage `json:"data,omitempty"`
}

func (a *App) runPanelAutonomy(ctx context.Context, instance string) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		a.collectPanelAutonomy(ctx, instance, a.localPanelAutonomy)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-a.panelSnapshots.autonomyWake:
		}
	}
}

func (a *App) localPanelAutonomy(ctx context.Context, now time.Time) (map[string]any, bool) {
	// Loading/repair belongs to startup or an admitted operation. This reader
	// must not reload sidecars, migrate state, acquire authority or do any writes.
	a.autonomy.mu.Lock()
	ready := a.autonomy.loaded && a.autonomy.doc.Policy.Schema != 0
	a.autonomy.mu.Unlock()
	if !ready || a.Store == nil || ctx.Err() != nil {
		return nil, false
	}
	data := a.autonomyView(now)
	return data, ctx.Err() == nil
}

func (a *App) collectPanelAutonomy(ctx context.Context, instance string, collect func(context.Context, time.Time) (map[string]any, bool)) bool {
	generation, idle := a.Operations.IdleGeneration()
	if !idle || ctx.Err() != nil {
		return false
	}
	observation, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	started := time.Now().UTC()
	// Read-only catalog enrichment and journal observation happen outside the
	// gate. A completed intervening operation invalidates the entire image.
	data, ok := collect(observation, started)
	if !ok || observation.Err() != nil {
		return false
	}
	encoded, err := json.Marshal(data)
	if err != nil || len(encoded) > maxPanelSnapshotBytes {
		return false
	}
	release, err := a.Operations.ObserveExclusive(observation, &generation)
	if err != nil {
		return false
	}
	defer release()
	revision := uint64(1)
	if previous := a.panelSnapshots.autonomy.Load(); previous != nil {
		revision = previous.Revision + 1
	}
	a.panelSnapshots.autonomy.Store(&panelAutonomyPublication{instance, revision, started, encoded})
	return true
}

func (a *App) panelAutonomyAt(now time.Time) panelAutonomyResponse {
	value := panelAutonomyResponse{Schema: 1, State: "empty", Dataplane: "not-checked", MaxAgeSeconds: int64(panelAutonomyLifetime.Seconds())}
	if saved := a.panelSnapshots.autonomy.Load(); saved != nil {
		value.InstanceID, value.Revision = saved.InstanceID, saved.Revision
		observed := saved.ObservedAt
		value.ObservedAt = &observed
		age := now.Sub(observed)
		value.DataAgeMS = max(0, age.Milliseconds())
		value.State = "available"
		admission := a.Operations.Snapshot()
		if age >= 15*time.Second || admission.Exclusive || admission.Fenced {
			value.State = "retained"
		}
		if age >= panelAutonomyLifetime || age < -time.Second {
			value.State = "expired"
		} else {
			value.Data = saved.Data
		}
	}
	return value
}

func (a *App) panelAutonomy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, a.panelAutonomyAt(time.Now()))
}
