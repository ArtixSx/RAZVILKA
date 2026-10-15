package app

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/ArtixSx/razvilka/internal/community"
)

const panelCommunityBrowsePath = "/api/v1/panel/community"

type panelCommunityBrowseData struct {
	Entries []community.BrowseDefinition `json:"entries"`
}

func (a *App) publishPanelCommunityBrowse(ctx context.Context, instance string, now time.Time) bool {
	release, err := a.Operations.ObserveExclusive(ctx, nil)
	if err != nil {
		return false
	}
	defer release()
	entries, ok := a.Community.BrowseDefinitions()
	if !ok {
		return false
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	for i := 1; i < len(entries); i++ {
		if entries[i-1].ID == entries[i].ID {
			return false
		}
	}
	encoded, err := json.Marshal(panelCommunityBrowseData{Entries: entries})
	if err != nil || len(encoded) > maxPanelSnapshotBytes || ctx.Err() != nil {
		return false
	}
	revision := uint64(1)
	if previous := a.panelSnapshots.community.Load(); previous != nil {
		revision = previous.Revision + 1
	}
	a.panelSnapshots.community.Store(&panelSavedPublication{instance, revision, now.UTC(), encoded})
	return true
}

// The shared envelope describes capture age, never upstream refresh/access.
func (a *App) panelCommunityBrowseAt(now time.Time) panelDeviceBrowseResponse {
	value := panelDeviceBrowseResponse{Schema: 1, ObservedAt: now.UTC(), MaxAgeSeconds: 900, State: "empty", Dataplane: "not-checked"}
	if saved := a.panelSnapshots.community.Load(); saved != nil {
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
		if age >= panelSnapshotLifetime || age < -time.Second {
			value.State = "expired"
		} else {
			value.Data = saved.Data
		}
	}
	return value
}

func (a *App) panelCommunityBrowse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodHead {
		return
	}
	writeJSON(w, http.StatusOK, a.panelCommunityBrowseAt(time.Now()))
}
