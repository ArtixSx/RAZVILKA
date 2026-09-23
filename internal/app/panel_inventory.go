package app

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/engine"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

const panelInventoryPath = "/api/v1/panel/inventory"
const panelInventoryLifetime = 5 * time.Minute

// Inventory is a dated local observation, not route health or Apply authority.
// Release-source CheckedAt is kept independently from local ObservedAt.
type panelInventoryData struct {
	Components []components.View    `json:"components"`
	Engines    []engine.Status      `json:"engines"`
	System     systemprobe.Snapshot `json:"system"`
}

type panelInventoryPublication struct {
	InstanceID string
	Revision   uint64
	ObservedAt time.Time
	Data       json.RawMessage
}

type panelInventoryResponse struct {
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

func (a *App) runPanelInventory(ctx context.Context, instance string) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	next := time.Time{}
	for {
		if !time.Now().Before(next) && a.collectPanelInventory(ctx, instance, a.localPanelInventory) {
			next = time.Now().Add(30 * time.Second)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-a.panelSnapshots.inventoryWake:
			next = time.Time{}
		}
	}
}

func (a *App) localPanelInventory(ctx context.Context) (panelInventoryData, error) {
	data := panelInventoryData{Components: []components.View{}, Engines: []engine.Status{}}
	if a.Components != nil {
		views, err := a.Components.Observe(ctx) // Never opkg update / downloads.
		if err != nil {
			return data, err
		}
		data.Components = views
	}
	if err := ctx.Err(); err != nil {
		return data, err
	}
	data.Engines = engine.Visible(a.engineInventorySnapshot())
	mergeComponentRuntimes(data.Components, data.Engines)
	// Version commands are not repeated for the engine strip. Use the package
	// observation only for the same installed component, retaining its source.
	for i := range data.Engines {
		for _, component := range data.Components {
			if component.ID == data.Engines[i].ID && component.Installed {
				data.Engines[i].Version = component.InstalledVersion
			}
		}
	}
	data.System = systemprobe.ProbeContext(ctx)
	return data, ctx.Err()
}

func (a *App) collectPanelInventory(ctx context.Context, instance string, collect func(context.Context) (panelInventoryData, error)) bool {
	generation, idle := a.Operations.IdleGeneration()
	if !idle || ctx.Err() != nil {
		return false
	}
	observation, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	started := time.Now().UTC()
	data, err := collect(observation) // No application lease while running commands.
	if err != nil || observation.Err() != nil {
		return false
	}
	encoded, err := json.Marshal(data)
	if err != nil || len(encoded) > maxPanelSnapshotBytes {
		return false
	}
	// Even a completed intervening operation invalidates the mixed observation.
	// Publication holds only this short memory lease, never command/cleanup time.
	release, err := a.Operations.ObserveExclusive(observation, &generation)
	if err != nil {
		return false
	}
	defer release()
	revision := uint64(1)
	if previous := a.panelSnapshots.inventory.Load(); previous != nil {
		revision = previous.Revision + 1
	}
	a.panelSnapshots.inventory.Store(&panelInventoryPublication{instance, revision, started, encoded})
	return true
}

func (a *App) panelInventoryAt(now time.Time) panelInventoryResponse {
	value := panelInventoryResponse{Schema: 1, State: "empty", Dataplane: "not-checked", MaxAgeSeconds: int64(panelInventoryLifetime.Seconds())}
	if saved := a.panelSnapshots.inventory.Load(); saved != nil {
		value.InstanceID, value.Revision = saved.InstanceID, saved.Revision
		observed := saved.ObservedAt
		value.ObservedAt = &observed
		age := now.Sub(observed)
		value.DataAgeMS = max(0, age.Milliseconds())
		value.State = "available"
		admission := a.Operations.Snapshot()
		if age >= time.Minute || admission.Exclusive || admission.Fenced {
			value.State = "retained"
		}
		if age >= panelInventoryLifetime || age < -time.Second {
			value.State = "expired"
		} else {
			value.Data = saved.Data
		}
	}
	return value
}

func (a *App) panelInventory(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, a.panelInventoryAt(time.Now()))
}
