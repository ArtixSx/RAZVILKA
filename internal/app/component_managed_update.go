package app

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// managedComponentUpdate updates NFQWS2 while its routes stay in use (plan
// M01). The check requires the user's configuration to survive the package
// change, adopts the package's new init into the ownership lease, and asks
// the service and any routes that were live before to be live afterwards.
func (a *App) managedComponentUpdate(w http.ResponseWriter, r *http.Request, id string) {
	if a.Dataplane == nil {
		http.Error(w, "dataplane manager is unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	check, err := a.nfqws2UpdateCheck(ctx)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "component": id, "code": "RUNTIME_STATE_UNKNOWN"})
		return
	}
	_ = a.Components.RecordOperation(id, "update", "running", "Обновление при работающих маршрутах: проверка и откат подготовлены")
	result, err := a.Components.ManagedUpdate(ctx, id, check)
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, components.ErrRollbackPackageMissing) {
			code = http.StatusConflict
		}
		_ = a.Components.RecordOperation(id, "update", "failed", err.Error())
		writeJSON(w, code, map[string]any{"error": err.Error(), "output": result.Output, "component": id})
		return
	}
	_ = a.Components.RecordOperation(id, "update", "succeeded", "Новая версия проверена при работающих маршрутах")
	writeJSON(w, http.StatusOK, result)
}

func (a *App) nfqws2UpdateCheck(ctx context.Context) (func(context.Context) error, error) {
	running, config, err := a.Dataplane.NFQWS2ServiceState(ctx)
	if err != nil {
		return nil, err
	}
	committed, exists, err := a.Dataplane.Committed()
	if err != nil {
		return nil, err
	}
	usesNFQWS2 := false
	if exists && committed.State == "committed" {
		for _, route := range committed.Routes {
			if dataplane.AdapterID(route.Resolved) == "nfqws2" {
				usesNFQWS2 = true
				break
			}
		}
	}
	liveBefore := usesNFQWS2 && a.Dataplane.ObserveCommittedRuntime(ctx, committed) == nil
	return func(ctx context.Context) error {
		runningNow, configNow, err := a.Dataplane.NFQWS2ServiceState(ctx)
		if err != nil {
			return err
		}
		if !bytes.Equal(configNow, config) {
			return errors.New("the package replaced nfqws2.conf; the previous configuration and version are restored")
		}
		if _, _, err := a.Dataplane.AdoptNFQWS2PackageInit(ctx, ""); err != nil && !errors.Is(err, dataplane.ErrNFQWS2NotOwned) {
			return err
		}
		if running && !runningNow {
			return errors.New("NFQWS2 service is not running after the package change")
		}
		if liveBefore {
			return a.Dataplane.ObserveCommittedRuntime(ctx, committed)
		}
		return nil
	}, nil
}

// cacheManagedRollbackPackages keeps a rollback copy of installed managed
// components after an explicit version check; failures only mean the next
// in-use update will ask for another check.
func (a *App) cacheManagedRollbackPackages(ctx context.Context) {
	for _, spec := range components.Specs() {
		if components.ManagedUpdateSupported(spec.ID) {
			_, _ = a.Components.CacheRollbackPackage(ctx, spec.ID)
		}
	}
}
