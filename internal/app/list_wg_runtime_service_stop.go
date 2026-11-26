package app

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Both ordinary runtime callers dispatch here before legacy unscoped admission.
// Only this App owner can keep native retirement and the Store CAS under one
// original private operation. Caller metadata never grants a native effect.
func (a *App) executeManagedWGServiceRuntime(parent context.Context, action string, expectedRevision uint64) (bool, serviceRuntimeOutcome) {
	if a == nil || a.Store == nil || a.Dataplane == nil {
		return false, serviceRuntimeOutcome{}
	}
	cfg := a.Store.Get()
	a.managedWGListMu.Lock()
	r := a.managedWGList
	a.managedWGListMu.Unlock()
	selected := false
	for _, state := range cfg.AppliedServices {
		selected = selected || state.Enabled && managedWGSelected(selectedRoute(state))
	}
	for _, route := range cfg.ServiceControl.SuspendedRoutes {
		selected = selected || managedWGSelected(route)
	}
	plan, found, planErr := a.Dataplane.Committed()
	if found && plan.LAN != nil && plan.LAN.Mode == "" {
		for _, route := range plan.Routes {
			selected = selected || managedWGSelected(route.Resolved)
		}
	}
	if r != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		selected = selected || r.active != nil || r.pending != nil || r.stopped != nil
	}
	// This read can wait behind another actual runtime operation. Re-read the
	// caller's CAS image after that wait before admitting any Stop effect.
	cfg = a.Store.Get()
	if !selected {
		return false, serviceRuntimeOutcome{}
	}
	fail := func(code, message string) (bool, serviceRuntimeOutcome) {
		return true, serviceRuntimeOutcome{Code: code, Message: message}
	}
	if cfg.Revision != expectedRevision {
		return fail("SERVICE_CONTROL_CHANGED", "Настройки изменились. Обновите состояние и повторите действие.")
	}
	if cfg.SafeMode {
		return fail("SERVICE_RUNTIME_SAFE_MODE", "Безопасный режим запрещает изменение маршрутов. Проверьте настройки безопасности.")
	}
	if action != "stop" {
		return fail("SERVICE_RUNTIME_CHECK_REQUIRED", "Для включения WireGuard нужна свежая проверка подключения и новый план применения.")
	}
	if planErr != nil || r == nil || !r.original() || r.preparing != nil {
		return fail("SERVICE_RUNTIME_CHANGED", "Исходный WireGuard маршрут требует проверки. Настройки сохранены.")
	}
	ctx, cancel := context.WithTimeout(parent, defaultDataplaneApplyTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return fail("SERVICE_RUNTIME_FAILED", "Остановка не завершена. Проверьте состояние и повторите действие.")
	}
	if r.pending != nil && !r.pending.pendingStop {
		if err := r.joinPending(ctx); err != nil {
			return fail("SERVICE_RUNTIME_FAILED", "Возврат исходной транзакции ещё не завершён. Откройте журнал.")
		}
		return fail("SERVICE_RUNTIME_CHANGED", "Исходная транзакция возвращена. Обновите состояние перед следующим действием.")
	}
	e := r.active
	if e == nil {
		e = r.stopped
	}
	if r.pending != nil {
		e = r.pending
	}
	if e == nil || e.self != e || e.runtime != r {
		return fail("SERVICE_RUNTIME_CHANGED", "Нет исходного владельца WireGuard маршрута. Настройки сохранены.")
	}
	if e.stopBefore == nil {
		if cfg.ServiceControl.Stopped || !found || plan.State != "committed" || plan.Revision != cfg.AppliedRevision || !sameManagedWireGuardAppliedPlan(plan, e.plan) {
			return fail("SERVICE_RUNTIME_CHANGED", "Применённое состояние изменилось. Обновите состояние перед остановкой.")
		}
		if _, err := e.appliedStopRoutes(cfg); err != nil {
			return fail("SERVICE_RUNTIME_CHANGED", "Область применённого маршрута изменилась. Откройте план перед остановкой.")
		}
		before := cfg
		e.stopBefore = &before
	} else {
		wanted := e.stopBefore
		if e.stopCommitted != nil {
			wanted = e.stopCommitted
		}
		if !reflect.DeepEqual(cfg, *wanted) {
			return fail("SERVICE_CONTROL_CHANGED", "Настройки изменились во время остановки. Откройте журнал; исходный владелец сохранён.")
		}
	}
	if err := r.stopServiceRuntimeLocked(ctx, e); err != nil {
		return fail("SERVICE_RUNTIME_FAILED", "Остановка ещё не подтверждена. Исходный владелец сохранён; откройте журнал и повторите действие.")
	}
	a.wakeReconciler()
	return true, serviceRuntimeOutcome{LiveApplied: true}
}

func (e *managedWGListExecution) appliedStopRoutes(cfg config.Config) (map[string]string, error) {
	if len(e.plan.Routes) == 0 || e.source == nil || e.source.self != e.source {
		return nil, dataplane.ErrWGOperationOwner
	}
	e.source.mu.Lock()
	serviceID := e.source.service
	original, issued := e.source.expected.AppliedServices[serviceID]
	e.source.mu.Unlock()
	if !issued || !original.Enabled {
		return nil, dataplane.ErrWGOperationOwner
	}
	resolved := map[string]string{}
	for _, route := range e.plan.Routes {
		state, ok := cfg.AppliedServices[serviceID]
		// The actual compiler gives this route a synthetic per-ingress ID and
		// narrows its traffic sources. Config retains the original logical
		// service and its configured sources, which may be empty under MAC
		// membership. Never mistake either representation for a new scope.
		if route.LogicalServiceID != serviceID || !ok || !reflect.DeepEqual(state, original) || selectedRoute(state) != route.Selected || !managedWGSelected(route.Resolved) || e.plan.LAN == nil {
			return nil, dataplane.ErrWGOperationOwner
		}
		matched := 0
		for _, ingress := range e.plan.LAN.Ingress {
			if !reflect.DeepEqual(route.Ingress, []string{ingress.Interface}) || len(route.Sources) != 1 {
				continue
			}
			source, err := netip.ParsePrefix(route.Sources[0])
			if err != nil || source.Masked() != source {
				return nil, dataplane.ErrWGOperationOwner
			}
			for _, cidr := range ingress.Sources {
				outer, err := netip.ParsePrefix(cidr)
				if err == nil && outer.Addr().Is4() == source.Addr().Is4() && outer.Bits() <= source.Bits() && outer.Contains(source.Addr()) {
					matched++
					break
				}
			}
		}
		if matched != 1 {
			return nil, dataplane.ErrWGOperationOwner
		}
		resolved[serviceID] = route.Resolved
	}
	for id, state := range cfg.AppliedServices {
		if state.Enabled && resolved[id] == "" {
			return nil, dataplane.ErrWGOperationOwner
		}
	}
	return resolved, nil
}

// Manager adds phase and service-evidence observations when it commits.
// Those documentary fields cannot change the original complete route intent.
func sameManagedWireGuardAppliedPlan(actual, original dataplane.Plan) bool {
	return actual.PlanID == original.PlanID && actual.Digest == original.Digest && actual.Revision == original.Revision &&
		actual.NetworkProfileID == original.NetworkProfileID && actual.SchemaVersion == original.SchemaVersion && actual.CreatedAt == original.CreatedAt &&
		actual.SafeMode == original.SafeMode && actual.Ready == original.Ready && actual.Noop == original.Noop && actual.RouteCount == original.RouteCount &&
		reflect.DeepEqual(actual.LAN, original.LAN) && reflect.DeepEqual(actual.DNS, original.DNS) && actual.SuspendDNS == original.SuspendDNS && actual.DiscardDNS == original.DiscardDNS &&
		reflect.DeepEqual(actual.Routes, original.Routes) && reflect.DeepEqual(actual.Actions, original.Actions) && reflect.DeepEqual(actual.Adapters, original.Adapters) &&
		reflect.DeepEqual(actual.RetiringAdapters, original.RetiringAdapters) && reflect.DeepEqual(actual.CanaryAdapters, original.CanaryAdapters) &&
		reflect.DeepEqual(actual.EngineDrafts, original.EngineDrafts) && reflect.DeepEqual(actual.ResourceConflicts, original.ResourceConflicts) &&
		reflect.DeepEqual(actual.Host, original.Host) && reflect.DeepEqual(actual.Protocol, original.Protocol) && reflect.DeepEqual(actual.Blockers, original.Blockers) &&
		reflect.DeepEqual(actual.Warnings, original.Warnings) && actual.RequiredEvidence == original.RequiredEvidence
}

func (r *ManagedWGListRuntime) stopServiceRuntimeLocked(ctx context.Context, e *managedWGListExecution) error {
	var c context.Context
	var closeOperation, release func()
	var cleanup *operationgate.ExclusiveCleanupReview
	var cancel context.CancelFunc
	if r.pending != nil {
		if r.pending != e || !e.pendingStop || e.pendingContext == nil || e.pendingCloseOperation == nil || e.pendingRelease == nil {
			return dataplane.ErrWGOperationOwner
		}
		c, cancel = context.WithTimeout(context.WithoutCancel(e.pendingContext), 15*time.Second)
		defer cancel()
		_, op, err := r.executionFor(c)
		if err != nil {
			return err
		}
		cleanup, closeOperation, release = op.cleanup, e.pendingCloseOperation, e.pendingRelease
	} else {
		var err error
		c, release, err = r.app.privateExclusiveOperation(componentStopContext(ctx, "stop"))
		if err != nil {
			if e.terminal == nil && e.stopCommitted == nil {
				e.stopBefore = nil
			}
			return err
		}
		cleanup, err = r.app.Operations.ReviewExclusiveCleanup(c)
		if err != nil {
			release()
			return err
		}
		if err := r.policy.control.CurrentForCleanupOperation(c, cleanup); err != nil {
			release()
			return err
		}
		c, cancel = context.WithTimeout(context.WithoutCancel(c), 15*time.Second)
		defer cancel()
		c, closeOperation, err = r.operation(c, e, cleanup)
		if err != nil {
			release()
			return err
		}
	}
	keep := false
	defer func() {
		if !keep {
			closeOperation()
			release()
		}
	}()
	nativeAttempted := e.terminal != nil
	err := cleanup.WithCurrent(c, func() error {
		wanted := e.stopBefore
		if e.stopCommitted != nil {
			wanted = e.stopCommitted
		}
		if wanted == nil || !reflect.DeepEqual(r.app.Store.Get(), *wanted) {
			return config.ErrRevisionChanged
		}
		if e.terminal == nil {
			actual, found, err := r.manager.Committed()
			if err != nil || !found || actual.State != "committed" || !sameManagedWireGuardAppliedPlan(actual, e.plan) {
				return errors.Join(dataplane.ErrWGOperationOwner, err)
			}
			nativeAttempted = true
			terminal, err := r.manager.StopRetainedManagedWG(c, cleanup)
			if err != nil {
				return err
			}
			e.terminal = terminal
			r.stopped, r.active = e, nil
		}
		if err := e.terminal.ObserveRetired(c, cleanup); err != nil {
			return err
		}
		if e.stopCommitted == nil {
			if e.stopBefore == nil || !reflect.DeepEqual(r.app.Store.Get(), *e.stopBefore) {
				return config.ErrRevisionChanged
			}
			resolved, err := e.appliedStopRoutes(*e.stopBefore)
			if err != nil {
				return err
			}
			if _, err := r.app.Store.CommitServiceRuntime(true, resolved, e.stopBefore.Revision); err != nil {
				return err
			}
			committed := r.app.Store.Get()
			e.stopCommitted = &committed
		}
		if e.stopBefore == nil || e.stopCommitted.Revision != e.stopBefore.Revision+1 || !e.stopCommitted.ServiceControl.Stopped || !reflect.DeepEqual(r.app.Store.Get(), *e.stopCommitted) {
			return config.ErrRevisionChanged
		}
		_, err := r.manager.CommitRetiredManagedWG(c, e.terminal, cleanup, e.stopCommitted.Revision)
		return errors.Join(err, r.policy.control.CurrentForCleanupOperation(c, cleanup))
	})
	if err != nil {
		if !nativeAttempted {
			e.stopBefore = nil
			return err
		}
		e.pendingContext, e.pendingCloseOperation, e.pendingRelease = c, closeOperation, release
		e.pendingStop = true
		r.pending = e
		keep = true
		r.app.Operations.FenceJournal()
		return err
	}
	e.pendingContext, e.pendingCloseOperation, e.pendingRelease = nil, nil, nil
	r.pending, r.active, r.stopped = nil, nil, e
	return nil
}
