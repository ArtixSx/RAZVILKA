package app

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"time"
)

const panelDeviceBrowsePath = "/api/v1/panel/devices"
const panelDeviceBrowseLifetime = 15 * time.Minute

// Saved metadata for browsing only. KnownAddresses and LastSeenAt are historical:
// neither this image nor its publication revision authorizes discovery, a device
// binding, a route, or a write. Deliberately do not embed devices.Device.
type panelBrowseDevice struct {
	ID             string   `json:"id"`
	Name           string   `json:"name,omitempty"`
	Group          string   `json:"group,omitempty"`
	Hostname       string   `json:"hostname,omitempty"`
	KnownAddresses []string `json:"known_addresses"`
	Interface      string   `json:"interface,omitempty"`
	LastSeenAt     string   `json:"last_seen_at,omitempty"`
}

type panelDeviceBrowseData struct {
	Devices []panelBrowseDevice `json:"devices"`
}

type panelDeviceBrowseResponse struct {
	Schema        int             `json:"schema"`
	InstanceID    string          `json:"instance_id"`
	Revision      uint64          `json:"revision"`
	GeneratedAt   *time.Time      `json:"generated_at"`
	ObservedAt    time.Time       `json:"observed_at"`
	DataAgeMS     int64           `json:"data_age_ms"`
	MaxAgeSeconds int64           `json:"max_age_seconds"`
	State         string          `json:"state"`
	Dataplane     string          `json:"dataplane"`
	Data          json.RawMessage `json:"data,omitempty"`
}

func (a *App) publishPanelDeviceBrowse(ctx context.Context, instance string, now time.Time) bool {
	release, err := a.Operations.ObserveExclusive(ctx, nil)
	if err != nil {
		return false
	}
	defer release()
	if a.Devices == nil {
		return false // Unavailable is not a successfully observed empty registry.
	}
	data := panelDeviceBrowseData{Devices: []panelBrowseDevice{}}
	// Known clones the in-memory registry only. Never use List/ListWithStatus:
	// those discover devices and can persist metadata even for a GET request.
	for _, device := range a.Devices.Known() {
		addresses := slices.Clone(device.IPs)
		if addresses == nil {
			addresses = []string{}
		}
		data.Devices = append(data.Devices, panelBrowseDevice{
			ID: device.ID, Name: device.Name, Group: device.Group, Hostname: device.Hostname,
			KnownAddresses: addresses, Interface: device.Interface, LastSeenAt: device.LastSeenAt,
		})
	}
	sort.Slice(data.Devices, func(i, j int) bool { return data.Devices[i].ID < data.Devices[j].ID })
	encoded, err := json.Marshal(data)
	if err != nil || len(encoded) > maxPanelSnapshotBytes || ctx.Err() != nil {
		return false
	}
	revision := uint64(1)
	if previous := a.panelSnapshots.devices.Load(); previous != nil {
		revision = previous.Revision + 1
	}
	// Encoding detaches all bytes from manager-owned metadata. Generated is the
	// memory capture time, not a new observation of device presence or addresses.
	a.panelSnapshots.devices.Store(&panelSavedPublication{instance, revision, now.UTC(), encoded})
	return true
}

func (a *App) panelDeviceBrowseAt(now time.Time) panelDeviceBrowseResponse {
	value := panelDeviceBrowseResponse{Schema: 1, ObservedAt: now.UTC(),
		MaxAgeSeconds: int64(panelDeviceBrowseLifetime.Seconds()), State: "empty", Dataplane: "not-checked"}
	if saved := a.panelSnapshots.devices.Load(); saved != nil {
		value.InstanceID, value.Revision = saved.InstanceID, saved.Revision
		generated := saved.Generated
		value.GeneratedAt = &generated
		age := now.Sub(generated)
		value.DataAgeMS = max(0, age.Milliseconds())
		value.State = "available"
		admission := a.Operations.Snapshot()
		if age >= 10*time.Second || admission.Exclusive || admission.Fenced {
			value.State = "retained"
		}
		if age >= panelDeviceBrowseLifetime || age < -time.Second {
			value.State = "expired"
		} else {
			value.Data = saved.Data
		}
	}
	return value
}

func (a *App) panelDeviceBrowse(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, a.panelDeviceBrowseAt(time.Now()))
}
