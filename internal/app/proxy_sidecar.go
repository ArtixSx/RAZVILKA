package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
)

// The setting is a next-boot choice. Neither GET nor PUT reconstructs an
// adapter, stops a service, changes routing, or turns a receipt into health.
func (a *App) proxySidecar(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		methodNotAllowed(w)
		return
	}
	if a.Store == nil {
		http.Error(w, "configuration owner unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodPut {
		var input struct {
			Backend          *string `json:"backend"`
			ExpectedRevision *uint64 `json:"expected_revision"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.Backend == nil || input.ExpectedRevision == nil || config.ValidateProxySidecar(*input.Backend) != nil {
			http.Error(w, "a known backend and exact revision are required", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		admitted, release, err := a.privateExclusiveOperation(ctx)
		if err != nil {
			a.writeOperationFailure(w, err)
			return
		}
		defer release()
		cfg := a.Store.Get()
		if cfg.Revision != *input.ExpectedRevision {
			writeJSON(w, http.StatusConflict, map[string]any{"not_started": true, "error": "Настройки изменились. Прочитайте актуальную редакцию."})
			return
		}
		if a.Dataplane == nil || !a.proxySidecarSelectionInactive(cfg) {
			writeJSON(w, http.StatusConflict, map[string]any{"not_started": true, "error": "Сначала остановите сервисы. Нужна исходная проверка отсутствия управляемых процессов и сетевых ресурсов."})
			return
		}
		if err := a.Dataplane.VerifyRuntimeInactive(admitted); err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"not_started": true, "error": "Отсутствие исходных процессов и сетевых ресурсов не подтверждено. Выбор не изменён."})
			return
		}
		if config.EffectiveProxySidecar(*input.Backend) == "hev" {
			if _, err := a.Components.CheckInstalledHEV(admitted); err != nil {
				writeJSON(w, http.StatusConflict, map[string]any{"not_started": true, "error": "Проверенная установка HEV 2.17.1 и исходная квитанция не подтверждены."})
				return
			}
		}
		if err := a.Store.SetProxySidecar(*input.ExpectedRevision, *input.Backend); err != nil {
			code := http.StatusInternalServerError
			if errors.Is(err, config.ErrRevisionChanged) {
				code = http.StatusConflict
			}
			http.Error(w, "boot backend was not saved; read current settings", code)
			return
		}
		a.wakePanelSnapshot()
	}
	cfg := a.Store.Get()
	requested := config.EffectiveProxySidecar(cfg.ProxySidecar)
	current := config.EffectiveProxySidecar(a.ProxySidecarBoot)
	writeJSON(w, http.StatusOK, map[string]any{"schema": 1, "backend": requested, "boot_backend": current, "revision": cfg.Revision, "restart_required": requested != current, "live_applied": false, "services_stopped": cfg.ServiceControl.Stopped, "available": nil, "reason": "original-runtime-inactivity-and-installed-owner-admission-required", "backends": []map[string]string{{"id": "sing-box", "name": "Sing-box · текущий стандартный TUN"}, {"id": "hev", "name": "HEV 2.17.1 · отдельный SOCKS5 TUN"}}})
}

func (a *App) proxySidecarSelectionInactive(cfg config.Config) bool {
	if cfg.ServiceControl.Stopped {
		return true
	}
	for _, states := range []map[string]config.ServiceState{cfg.Services, cfg.AppliedServices, cfg.ServiceControl.SuspendedServices} {
		for _, state := range states {
			if state.Enabled {
				return false
			}
		}
	}
	if len(cfg.ServiceControl.SuspendedRoutes) != 0 || a.Dataplane == nil {
		return false
	}
	committed, exists, err := a.Dataplane.Committed()
	return err == nil && (!exists || len(committed.Routes) == 0 && len(committed.Adapters) == 0 && len(committed.RetiringAdapters) == 0)
}
