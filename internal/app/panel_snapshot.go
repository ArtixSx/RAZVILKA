package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/routerstats"
)

const panelSnapshotPath = "/api/v1/panel/snapshot"
const panelSnapshotLifetime = 15 * time.Minute
const maxPanelSnapshotBytes = 256 << 10

// These are presentation DTOs, never authority for an Apply or a health proof.
// In particular an applied AUTO choice is not the resolved/observed route.
type panelSavedService struct {
	ID             string                `json:"id"`
	Name           string                `json:"name"`
	Category       string                `json:"category"`
	Custom         bool                  `json:"custom"`
	Desired        serviceRouteStateView `json:"desired"`
	Applied        serviceRouteStateView `json:"applied"`
	Sources        []string              `json:"sources"`
	AppliedSources []string              `json:"applied_sources"`
	RouteDirty     bool                  `json:"route_dirty"`
	SourcesDirty   bool                  `json:"sources_dirty"`
}

type panelSavedConfig struct {
	Revision        uint64 `json:"revision"`
	AppliedRevision uint64 `json:"applied_revision"`
	SafeMode        bool   `json:"safe_mode"`
	Stopped         bool   `json:"stopped"`
	Mode            string `json:"mode"`
}

type panelSavedSource struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Kind           string    `json:"kind"`
	Enabled        bool      `json:"enabled"`
	AppliedEnabled bool      `json:"applied_enabled"`
	CacheStatus    string    `json:"cache_status"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type panelSavedJob struct {
	ID        uint64 `json:"id"`
	Kind      string `json:"kind"`
	State     string `json:"state"`
	Phase     string `json:"phase"`
	Total     int    `json:"total"`
	Completed int    `json:"completed"`
}

type panelSavedData struct {
	Config   panelSavedConfig    `json:"config"`
	Services []panelSavedService `json:"services"`
	Sources  []panelSavedSource  `json:"sources"`
}

// The immutable encoded document is detached from all Store-owned slices.
// The HTTP path only loads this pointer; it never acquires operation admission.
type panelSavedPublication struct {
	InstanceID string
	Revision   uint64
	Generated  time.Time
	Data       json.RawMessage
}

type panelSnapshotState struct {
	once    sync.Once
	latest  atomic.Pointer[panelSavedPublication]
	wake    chan struct{}
	done    chan struct{}
	started bool // set before serving HTTP; lifecycle methods must not race startup
}

type panelSnapshotResponse struct {
	Schema        int                    `json:"schema"`
	InstanceID    string                 `json:"instance_id"`
	Revision      uint64                 `json:"revision"`
	GeneratedAt   *time.Time             `json:"generated_at"`
	ObservedAt    time.Time              `json:"observed_at"`
	DataAgeMS     int64                  `json:"data_age_ms"`
	MaxAgeSeconds int64                  `json:"max_age_seconds"`
	State         string                 `json:"state"`
	Dataplane     string                 `json:"dataplane"`
	Admission     operationgate.Snapshot `json:"admission"`
	Data          json.RawMessage        `json:"data,omitempty"`
	Job           *panelSavedJob         `json:"job"`
	Metrics       routerstats.Snapshot   `json:"metrics"`
}

// StartPanelSnapshots must run after boot Store/journal recovery, before HTTP.
// A single publisher captures memory-only settings under a short exclusive
// lease. It never waits for a worker, downloads lists, probes engines, resolves
// DNS or reads a transaction journal. Busy/recovery leaves the old image intact.
func (a *App) StartPanelSnapshots(ctx context.Context) {
	a.panelSnapshots.once.Do(func() {
		p := &a.panelSnapshots
		p.wake, p.done, p.started = make(chan struct{}, 1), make(chan struct{}), true
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			close(p.done)
			return // An unavailable presentation must not prevent recovery/Stop.
		}
		instance := hex.EncodeToString(id[:])
		a.publishPanelSnapshot(ctx, instance, time.Now())
		go func() {
			defer close(p.done)
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				case <-p.wake:
				}
				a.publishPanelSnapshot(ctx, instance, time.Now())
			}
		}()
	})
}

func (a *App) wakePanelSnapshot() {
	if !a.panelSnapshots.started {
		return
	}
	select {
	case a.panelSnapshots.wake <- struct{}{}:
	default:
	}
}

func (a *App) WaitPanelSnapshots(ctx context.Context) error {
	if !a.panelSnapshots.started {
		return nil
	}
	select {
	case <-a.panelSnapshots.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *App) publishPanelSnapshot(ctx context.Context, instance string, now time.Time) bool {
	release, err := a.Operations.Exclusive(ctx)
	if err != nil {
		return false
	}
	defer release()
	if a.Store == nil {
		return false
	}
	cfg := a.Store.Get()
	data := panelSavedData{Config: panelSavedConfig{Revision: cfg.Revision, AppliedRevision: cfg.AppliedRevision, SafeMode: cfg.SafeMode, Stopped: cfg.ServiceControl.Stopped, Mode: cfg.ServiceControl.EffectiveMode()}, Services: []panelSavedService{}, Sources: []panelSavedSource{}}
	// Do not use catalogSnapshot: source enrichment reads list files. Only
	// metadata is needed for navigation; definitions/proofs require a live read.
	definitions := append([]catalog.Service{}, a.Catalog.Services...)
	custom := map[string]bool{}
	if a.CustomServices != nil {
		for _, service := range a.CustomServices.List() {
			definitions = append(definitions, service)
			custom[service.ID] = true
		}
	}
	if len(definitions) > 512 {
		return false
	}
	for _, service := range definitions {
		desired, applied := cfg.Services[service.ID], cfg.AppliedServices[service.ID]
		data.Services = append(data.Services, panelSavedService{
			ID: service.ID, Name: service.Name, Category: service.Category, Custom: custom[service.ID],
			Desired: serviceRouteStateView{Enabled: desired.Enabled, Route: selectedRoute(desired), Source: "saved-settings"},
			Applied: serviceRouteStateView{Enabled: applied.Enabled, Route: selectedRoute(applied), Source: "saved-settings"},
			Sources: slices.Clone(desired.Sources), AppliedSources: slices.Clone(applied.Sources),
			RouteDirty:   desired.Enabled != applied.Enabled || selectedRoute(desired) != selectedRoute(applied),
			SourcesDirty: !stringSlicesEqual(desired.Sources, applied.Sources),
		})
	}
	sort.Slice(data.Services, func(i, j int) bool { return data.Services[i].ID < data.Services[j].ID })
	if a.Sources != nil {
		for _, source := range a.Sources.List() { // List is memory-only; URLs/errors are intentionally excluded.
			data.Sources = append(data.Sources, panelSavedSource{source.ID, source.Name, source.Kind, source.Enabled, source.AppliedEnabled, source.CacheStatus, source.UpdatedAt})
		}
	}
	encoded, err := json.Marshal(data)
	if err != nil || len(encoded) > maxPanelSnapshotBytes || ctx.Err() != nil {
		return false
	}
	revision := uint64(1)
	if previous := a.panelSnapshots.latest.Load(); previous != nil {
		revision = previous.Revision + 1
	}
	a.panelSnapshots.latest.Store(&panelSavedPublication{instance, revision, now.UTC(), encoded})
	return true
}

func (a *App) panelSnapshotAt(now time.Time) panelSnapshotResponse {
	value := panelSnapshotResponse{Schema: 1, State: "empty", Dataplane: "not-checked", ObservedAt: now.UTC(), MaxAgeSeconds: int64(panelSnapshotLifetime.Seconds()), Admission: a.Operations.Snapshot()}
	if saved := a.panelSnapshots.latest.Load(); saved != nil {
		value.InstanceID, value.Revision = saved.InstanceID, saved.Revision
		generated := saved.Generated
		value.GeneratedAt = &generated
		age := now.Sub(saved.Generated)
		value.DataAgeMS = max(0, age.Milliseconds())
		value.State = "available"
		if age >= 10*time.Second || value.Admission.Exclusive || value.Admission.Fenced {
			value.State = "retained"
		}
		if age >= panelSnapshotLifetime || age < -time.Second {
			value.State = "expired"
		} else {
			value.Data = saved.Data
		}
	}
	// Progress is a separate observation, not part of the configuration revision.
	// Only allowlisted identifiers/counters are exposed, never raw errors, URLs,
	// profile bodies or keys. Metrics are the sampler's already collected value.
	a.nodeChecks.mu.Lock()
	if job := a.nodeChecks.job; job != nil {
		value.Job = &panelSavedJob{job.ID, job.Mode, job.State, job.Phase, job.Total, job.Completed}
	}
	a.nodeChecks.mu.Unlock()
	value.Metrics = a.Stats.Latest()
	return value
}

func (a *App) panelSnapshot(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, a.panelSnapshotAt(time.Now()))
}
