package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engine"
)

// managedComponentUpdate updates a component while its routes stay in use
// (plan M01). For NFQWS2 the check requires the user's configuration to survive
// the package change, adopts the package's new init into the ownership lease,
// and asks the service and any routes that were live before to be live
// afterwards. Proxy engines are checked in an isolated canary instead.
// updateComponent updates one installed component outside an HTTP request.
func (a *App) updateComponent(ctx context.Context, id string) error {
	if a.Components == nil {
		return errors.New("component manager disabled")
	}
	plan, err := a.Components.Plan(ctx, id, "update", false)
	if err != nil {
		return err
	}
	a.enrichComponentPlan(&plan)
	if !plan.Ready {
		return errors.New("component lifecycle plan is blocked")
	}
	if a.managedUpdateInUse(id) {
		if a.Dataplane == nil {
			return errors.New("dataplane manager is unavailable")
		}
		var check func(context.Context) error
		success := "Новая версия проверена при работающих маршрутах (ночное обслуживание)"
		if id == "nfqws2" {
			check, err = a.nfqws2UpdateCheck(ctx)
		} else {
			check, _, err = a.proxyUpdateCheck(ctx, id)
		}
		if err != nil {
			return err
		}
		_ = a.Components.RecordOperation(id, "update", "running", "Ночное обслуживание: обновление с проверкой и откатом")
		if _, err = a.Components.ManagedUpdate(ctx, id, check); err != nil {
			_ = a.Components.RecordOperation(id, "update", "failed", err.Error())
			return err
		}
		_ = a.Components.RecordOperation(id, "update", "succeeded", success)
		return nil
	}
	if blocker := a.componentRuntimeBlocker(id, "update"); blocker != nil {
		return errors.New("component runtime blocks the update")
	}
	_ = a.Components.RecordOperation(id, "update", "running", "Ночное обслуживание: обновление")
	if _, err = a.Components.Apply(ctx, id); err != nil {
		_ = a.Components.RecordOperation(id, "update", "failed", err.Error())
		return err
	}
	_ = a.Components.RecordOperation(id, "update", "succeeded", "Фактическое состояние компонента повторно проверено (ночное обслуживание)")
	if components.ManagedUpdateSupported(id) {
		_, _ = a.Components.CacheRollbackPackage(ctx, id)
	}
	return nil
}

func (a *App) managedComponentUpdate(w http.ResponseWriter, r *http.Request, id string) {
	if a.Dataplane == nil {
		http.Error(w, "dataplane manager is unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Minute)
	defer cancel()
	var check func(context.Context) error
	var err error
	success := "Новая версия проверена при работающих маршрутах"
	if id == "nfqws2" {
		check, err = a.nfqws2UpdateCheck(ctx)
	} else {
		var adapters []string
		check, adapters, err = a.proxyUpdateCheck(ctx, id)
		if errors.Is(err, errProxyPrecheck) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "Маршруты этого обхода не проходят изолированную проверку и на текущей версии, поэтому обновление с проверкой сейчас невозможно. Проверьте подключения сервисов, затем повторите обновление.", "component": id, "code": "MANAGED_UPDATE_PRECHECK_FAILED"})
			return
		}
		if len(adapters) > 0 {
			success = "Новая версия проверена изолированно на действующих маршрутах. Работающие процессы перейдут на неё при следующем применении или перезапуске."
		}
	}
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
	_ = a.Components.RecordOperation(id, "update", "succeeded", success)
	result.Output += "\n" + success
	writeJSON(w, http.StatusOK, result)
}

// managedUpdateInUse reports whether an update goes through the checked in-use
// path: the component supports it and its runtime runs or routes reference
// it. An unused component is updated plainly and needs no rollback copy;
// package sources usually keep only the newest version, so requiring a copy
// there would block updates for good.
func (a *App) managedUpdateInUse(id string) bool {
	if !components.ManagedUpdateSupported(id) {
		return false
	}
	if desired, applied := a.componentServiceReferences(id); len(desired) > 0 || len(applied) > 0 {
		return true
	}
	for _, runtime := range (engine.Detector{}).Inventory() {
		if runtime.ID == id && runtime.Running {
			return true
		}
	}
	return false
}

// managedProxyAdapters lists the committed adapters whose runtime uses the
// component's binary: Sing-box is also the TUN sidecar of Xray and USQUE, and
// both WireGuard components share the wireguard-tools package.
var managedProxyAdapters = map[string][]string{
	"sing-box":  {"sing-box", "xray", "usque"},
	"xray":      {"xray"},
	"usque":     {"usque"},
	"warp-wg":   {"warp-wg", "wireguard"},
	"wireguard": {"warp-wg", "wireguard"},
}

var errProxyPrecheck = errors.New("committed routes do not pass the isolated check with the installed version")

// proxyUpdateCheck proves a proxy engine update on the committed routes
// without touching them: running processes keep the binary they started with,
// and the new one is staged, natively validated and started in the isolated
// canary. The same check must pass with the installed version first, so a
// failure after the package change is attributed to the new version.
func (a *App) proxyUpdateCheck(ctx context.Context, id string) (func(context.Context) error, []string, error) {
	committed, exists, err := a.Dataplane.Committed()
	if err != nil {
		return nil, nil, err
	}
	var adapters []string
	if exists && committed.State == "committed" && !committed.SafeMode && !committed.Noop {
		for _, adapter := range managedProxyAdapters[id] {
			if slices.Contains(committed.Adapters, adapter) {
				adapters = append(adapters, adapter)
			}
		}
	}
	check := func(ctx context.Context) error {
		for _, adapter := range adapters {
			if err := a.Dataplane.ProbeCandidate(ctx, committed, adapter); err != nil {
				return fmt.Errorf("isolated check of %s routes failed: %w", adapter, err)
			}
		}
		return nil
	}
	if err := check(ctx); err != nil {
		return nil, adapters, fmt.Errorf("%w: %w", errProxyPrecheck, err)
	}
	return check, adapters, nil
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
