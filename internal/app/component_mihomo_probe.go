package app

import (
	"context"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type mihomoProbeState struct {
	mu         sync.Mutex
	adapter    *dataplane.MihomoProbeAdapter
	manager    *dataplane.Manager
	components *components.Manager
	provider   *netidentity.Provider
	held       *mihomoProbeRetention
}

const mihomoProbeRecoveryPath = "/api/v1/extension-lab/mihomo/probe"

type mihomoProbeRetention struct {
	ctx      context.Context
	release  func()
	control  *operationgate.ControlEpochReview
	source   *components.MihomoProbeSource
	adapter  *dataplane.MihomoProbeAdapter
	done     chan struct{}
	retrying bool
}

// ConfigureMihomoProbe binds one startup provider and the original installed
// component/dataplane managers. A request never constructs a replacement owner.
func (a *App) ConfigureMihomoProbe(provider *netidentity.Provider) error {
	if a == nil || provider == nil || a.Components == nil || a.Dataplane == nil {
		return components.ErrRecoveryAuthority
	}
	a.mihomoProbe.mu.Lock()
	defer a.mihomoProbe.mu.Unlock()
	s := &a.mihomoProbe
	if s.adapter != nil {
		if s.manager == a.Dataplane && s.components == a.Components && s.provider == provider {
			return nil
		}
		return components.ErrRecoveryAuthority
	}
	adapter := dataplane.NewMihomoProbeAdapter(a.Components, provider)
	if err := a.Dataplane.Register(adapter); err != nil {
		return err
	}
	s.adapter, s.manager, s.components, s.provider = adapter, a.Dataplane, a.Components, provider
	return nil
}

func (a *App) mihomoProbeRegistered() bool {
	a.mihomoProbe.mu.Lock()
	defer a.mihomoProbe.mu.Unlock()
	s := &a.mihomoProbe
	return s.adapter != nil && s.manager == a.Dataplane && s.components == a.Components && s.adapter.RegisteredWith(s.manager)
}

func writeMihomoProbeFailure(w http.ResponseWriter, pending bool) {
	code := "MIHOMO_SERVICE_PROBE_UNCONFIRMED"
	if pending {
		code = "MIHOMO_SERVICE_PROBE_CLEANUP_PENDING"
	}
	writeJSON(w, http.StatusConflict, map[string]any{"code": code, "recovery_required": pending, "service_verified": false, "live_applied": false, "draft_persisted": false})
}

func (a *App) probeMihomo(w http.ResponseWriter, r *http.Request, raw string, options backendprofile.MihomoOptions, review, serviceID string, revision *uint64) {
	if revision == nil || serviceID == "" {
		http.Error(w, "Выберите сервис каталога и обновите состояние настроек.", 400)
		return
	}
	if !a.mihomoProbeRegistered() || a.Store == nil || a.ComponentHistory == nil || a.ExecutionHistory == nil || a.SelfUpdateFiles == nil || a.Components.StateDir != managedComponentsState || a.Dataplane.StateRoot != filepath.Join(installpath.State, "dataplane") {
		writeMihomoProbeFailure(w, false)
		return
	}
	cfg := a.Store.Get()
	if cfg.Revision != *revision {
		writeMihomoProbeFailure(w, false)
		return
	}
	var service catalog.Service
	for _, candidate := range a.catalogSnapshot().Services {
		if candidate.ID == serviceID {
			service = defaultRouteCloneCatalogService(candidate)
			break
		}
	}
	// Use the same closed service definition consumed by the actual adapter.
	if _, err := dataplane.FrozenProbeService(dataplane.Route{LogicalServiceID: service.ID, ProbeService: &service, ProbeURL: service.ProbeURL}); err != nil {
		writeMihomoProbeFailure(w, false)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	heldCtx, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	a.mihomoProbe.mu.Lock()
	state := &a.mihomoProbe
	if state.held != nil || state.manager != a.Dataplane || state.components != a.Components {
		a.mihomoProbe.mu.Unlock()
		release()
		writeMihomoProbeFailure(w, true)
		return
	}
	held := &mihomoProbeRetention{ctx: context.WithoutCancel(heldCtx), release: release, adapter: state.adapter, done: make(chan struct{})}
	state.held = held
	a.mihomoProbe.mu.Unlock()
	normal := false
	defer func() {
		// Exceptional unwinds preserve the exact original cleanup owner.
		if !normal {
			a.Operations.FenceJournal()
		}
		close(held.done)
	}()
	finish := func() error {
		if held.adapter.Pending() {
			return components.ErrMihomoProbePending
		}
		if held.source != nil {
			if err := held.source.Close(); err != nil {
				return err
			}
			held.source = nil
		}
		if held.control != nil {
			if err := held.control.Close(); err != nil {
				return err
			}
			held.control = nil
		}
		a.mihomoProbe.mu.Lock()
		if a.mihomoProbe.held == held {
			a.mihomoProbe.held = nil
		}
		a.mihomoProbe.mu.Unlock()
		held.release()
		return nil
	}
	var result dataplane.MihomoServiceProbe
	err = a.ComponentHistory.CheckReadable(heldCtx)
	if err == nil {
		err = a.ExecutionHistory.CheckWrite(heldCtx, 4)
	}
	if err == nil {
		held.control, err = a.Operations.ReviewControlEpoch(heldCtx, a.SelfUpdateFiles.ControlRoot)
	}
	var env *mihomoProbeEnvironment
	if err == nil {
		env, err = newMihomoProbeEnvironment(heldCtx, a, cfg, service)
	}
	if err == nil {
		compiled, e := backendprofile.Mihomo(raw, options)
		err = e
		if err == nil && (options.Index < 0 || options.Index >= len(compiled.Source.Nodes)) {
			err = components.ErrMihomoNativeValidation
		}
		if err == nil {
			host := compiled.Source.Nodes[options.Index].Server
			endpoint, e := env.endpoint(heldCtx, host)
			err = e
			if err == nil {
				held.source, err = a.Components.ReviewMihomoProbe(heldCtx, raw, options, review, host, endpoint, a.hevForwardGuard(cfg, held.control))
			}
		}
	}
	if err == nil {
		checked := dataplane.WithReviewGuard(heldCtx, env.current)
		checked = dataplane.WithNodeResourceGuard(checked, env.resource)
		result, err = held.adapter.Check(checked, a.Dataplane, held.source, service, cfg.Revision, env.network, a.ComponentHistory, a.ExecutionHistory, held.control)
		if err == nil {
			err = env.current(heldCtx)
		}
	}
	cleanupErr := finish()
	normal = true
	if cleanupErr != nil {
		a.Operations.FenceJournal()
		writeMihomoProbeFailure(w, true)
		return
	}
	if err != nil || r.Context().Err() != nil || !a.Security.Authenticated(r) {
		writeMihomoProbeFailure(w, false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"probe": result, "review": review, "live_applied": false, "draft_persisted": false, "recovery_required": false})
}

// GET is observation only. POST can retry only the retained in-memory owner;
// it never acquires a new operation or reconstructs a process from a request.
func (a *App) mihomoProbeRecovery(w http.ResponseWriter, r *http.Request) {
	if !a.extensionAccess(w, r) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if r.Method == http.MethodGet {
		a.mihomoProbe.mu.Lock()
		held := a.mihomoProbe.held
		a.mihomoProbe.mu.Unlock()
		var recovery *bool
		if held == nil && a.Dataplane != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			required := a.Dataplane.CheckExecutionRecovery(ctx) != nil
			cancel()
			recovery = &required
		}
		writeJSON(w, 200, map[string]any{"owner_present": held != nil, "cleanup_confirmed": false, "execution_recovery_required": recovery, "live_applied": false, "lifecycle": a.runtimeLifecycle("mihomo")})
		return
	}
	var input struct {
		Confirm string `json:"confirm"`
	}
	if !extensionDecode(w, r, &input) {
		return
	}
	if input.Confirm != "RETRY_MIHOMO_PROBE_CLEANUP" {
		http.Error(w, "Подтвердите повтор завершения исходной проверки.", 400)
		return
	}
	a.mihomoProbe.mu.Lock()
	held := a.mihomoProbe.held
	if held == nil || held.retrying {
		a.mihomoProbe.mu.Unlock()
		writeMihomoProbeFailure(w, held != nil)
		return
	}
	select {
	case <-held.done:
	default:
		a.mihomoProbe.mu.Unlock()
		writeMihomoProbeFailure(w, true)
		return
	}
	held.retrying = true
	a.mihomoProbe.mu.Unlock()
	defer func() { a.mihomoProbe.mu.Lock(); held.retrying = false; a.mihomoProbe.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(held.ctx, 15*time.Second)
	defer cancel()
	var err error
	if held.adapter.Pending() {
		err = held.adapter.RetryCleanup(ctx)
	}
	if err == nil && held.source != nil {
		err = held.source.Close()
		if err == nil {
			held.source = nil
		}
	}
	if err == nil && held.control != nil {
		err = held.control.Close()
		if err == nil {
			held.control = nil
		}
	}
	if err != nil || held.adapter.Pending() {
		writeMihomoProbeFailure(w, true)
		return
	}
	a.mihomoProbe.mu.Lock()
	if a.mihomoProbe.held == held {
		a.mihomoProbe.held = nil
	}
	a.mihomoProbe.mu.Unlock()
	held.release()
	writeJSON(w, 200, map[string]any{"pending": false, "live_applied": false, "service_verified": false, "restart_required": true})
}
