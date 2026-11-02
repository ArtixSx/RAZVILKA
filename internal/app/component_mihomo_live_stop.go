package app

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"reflect"
	"strings"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Memory-only original Stop cursor. It retains comparison images and the
// original terminal across a failed CAS/ACK; serialized plans cannot mint it.
type mihomoLiveStop struct {
	manager           *dataplane.Manager
	store             *config.Store
	before, committed *config.Config
	terminal          *dataplane.MihomoLiveTerminal
	closing           bool // Only after original config CAS and both stopped-plan ACKs.
	cleanup           *operationgate.ExclusiveCleanupReview
	context           context.Context
	release           func()
}

func mihomoLivePlan(plan dataplane.Plan) bool {
	return len(plan.Routes) == 1 && strings.HasPrefix(plan.Routes[0].Resolved, "mihomo:node-")
}
func (a *App) observeCommittedMihomo(ctx context.Context, expected dataplane.Plan) (bool, error) {
	if !mihomoLivePlan(expected) {
		return false, nil
	}
	if a == nil || a.Dataplane == nil || expected.State != "committed" || !a.mihomoProbeRegistered() {
		return true, dataplane.ErrReviewChanged
	}
	current, found, err := a.Dataplane.Committed()
	if err != nil || !found || !reflect.DeepEqual(current, expected) {
		return true, errors.Join(dataplane.ErrReviewChanged, err)
	}
	held, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		return true, err
	}
	defer release()
	if err = a.Dataplane.CheckMihomoLive(held); err != nil {
		return true, err
	}
	current, found, err = a.Dataplane.Committed()
	if err != nil || !found || !reflect.DeepEqual(current, expected) {
		return true, errors.Join(dataplane.ErrReviewChanged, err)
	}
	return true, nil
}
func (a *App) executeMihomoServiceRuntime(parent context.Context, action string, revision uint64) (bool, serviceRuntimeOutcome) {
	if a == nil || a.Store == nil || a.Dataplane == nil {
		return false, serviceRuntimeOutcome{}
	}
	a.mihomoProbe.liveStopMu.Lock()
	defer a.mihomoProbe.liveStopMu.Unlock()
	cfg := a.Store.Get()
	plan, found, planErr := a.Dataplane.Committed()
	selected := found && mihomoLivePlan(plan) || a.Dataplane.HasPendingMihomoLive() || a.mihomoProbe.liveStop != nil || a.mihomoProbe.liveApply != nil
	for _, state := range cfg.AppliedServices {
		selected = selected || state.Enabled && strings.HasPrefix(selectedRoute(state), "mihomo:node-")
	}
	if !selected {
		return false, serviceRuntimeOutcome{}
	}
	fail := func(code, message string) (bool, serviceRuntimeOutcome) {
		return true, serviceRuntimeOutcome{Code: code, Message: message}
	}
	if cfg.Revision != revision {
		return fail("SERVICE_CONTROL_CHANGED", "Настройки изменились. Обновите состояние и повторите действие.")
	}
	if cfg.SafeMode {
		return fail("SERVICE_RUNTIME_SAFE_MODE", "Безопасный режим запрещает изменение маршрутов.")
	}
	if action != "stop" {
		return fail("SERVICE_RUNTIME_CHECK_REQUIRED", "Для включения Mihomo нужен новый план и свежая проверка выбранного узла.")
	}
	if planErr != nil || !a.mihomoProbeRegistered() {
		return fail("SERVICE_RUNTIME_CHANGED", "Исходный владелец Mihomo недоступен. Настройки сохранены.")
	}
	ctx, cancel := context.WithTimeout(parent, defaultDataplaneApplyTimeout)
	defer cancel()
	var held context.Context
	var release func()
	var cleanup *operationgate.ExclusiveCleanupReview
	var err error
	if pending := a.mihomoProbe.liveApply; pending != nil {
		if pending.manager != a.Dataplane || pending.release == nil || pending.cleanup == nil {
			return fail("SERVICE_RUNTIME_CHANGED", "Исходный владелец возврата изменился.")
		}
		held = context.WithoutCancel(pending.context)
		var done context.CancelFunc
		held, done = context.WithTimeout(held, defaultDataplaneApplyTimeout)
		defer done()
		release, cleanup = pending.release, pending.cleanup
	} else if retained := a.mihomoProbe.liveStop; retained != nil && retained.release != nil {
		held = context.WithoutCancel(retained.context)
		var done context.CancelFunc
		held, done = context.WithTimeout(held, defaultDataplaneApplyTimeout)
		defer done()
		release, cleanup = retained.release, retained.cleanup
	} else {
		held, release, err = a.privateExclusiveOperation(componentStopContext(ctx, "stop"))
		if err != nil {
			return fail("SERVICE_RUNTIME_FAILED", "Остановка пока недоступна. Проверьте журнал и повторите действие.")
		}
		cleanup, err = a.Operations.ReviewExclusiveCleanup(held)
		if err != nil {
			release()
			return fail("SERVICE_RUNTIME_FAILED", "Не удалось подтвердить исходную область остановки.")
		}
	}
	// An already-retained original admission must survive EVERY retry refusal,
	// including stale Store observations before the first cleanup callback.
	keep := a.mihomoProbe.liveApply != nil || a.mihomoProbe.liveStop != nil && a.mihomoProbe.liveStop.release != nil
	defer func() {
		if !keep {
			release()
		}
	}()
	if a.mihomoProbe.liveApply != nil && a.mihomoProbe.liveStop == nil {
		if err = a.Dataplane.JoinPendingMihomoLive(held, cleanup); err != nil {
			keep = true
			a.Operations.FenceJournal()
			return fail("SERVICE_RUNTIME_FAILED", "Возврат исходной транзакции ещё не подтверждён. Повторите остановку.")
		}
		a.mihomoProbe.liveApply = nil
		keep = false
		return fail("SERVICE_RUNTIME_CHANGED", "Исходная транзакция возвращена. Обновите состояние перед следующим действием.")
	}
	if a.Dataplane.HasPendingMihomoLive() && a.mihomoProbe.liveStop == nil && !a.Dataplane.HasPendingMihomoTransitHistory() {
		return fail("SERVICE_RUNTIME_CHANGED", "Исходная операция возврата не сохранена. Требуется проверка восстановления после перезапуска.")
	}
	cursor := a.mihomoProbe.liveStop
	if cursor == nil {
		if !found || !mihomoLivePlan(plan) || cfg.ServiceControl.Stopped || plan.Revision != cfg.AppliedRevision {
			return fail("SERVICE_RUNTIME_CHANGED", "Применённый маршрут изменился. Обновите состояние перед остановкой.")
		}
		before := cfg
		cursor = &mihomoLiveStop{manager: a.Dataplane, store: a.Store, before: &before}
		a.mihomoProbe.liveStop = cursor
	}
	wanted := cursor.before
	if cursor.committed != nil {
		wanted = cursor.committed
	}
	if cursor.manager != a.Dataplane || cursor.store != a.Store || wanted == nil || !reflect.DeepEqual(a.Store.Get(), *wanted) {
		return fail("SERVICE_CONTROL_CHANGED", "Настройки изменились во время остановки. Исходный владелец сохранён.")
	}
	completed := false
	// Register custody before the first possible native effect. A panic keeps
	// the same owner/review and still propagates unchanged to the caller.
	defer func() {
		if !completed {
			cursor.context, cursor.release, cursor.cleanup = context.WithoutCancel(held), release, cleanup
			keep = true
			a.Operations.FenceJournal()
		}
	}()
	err = func() error {
		if cursor.closing {
			// The root closing cursor may already have closed scope/native
			// comparison handles. Only the same in-memory terminal can resume;
			// replaying earlier observations here would strand that owner.
			if cursor.terminal == nil || cursor.committed == nil {
				return dataplane.ErrReviewChanged
			}
			return cursor.terminal.Close(held, cleanup)
		}
		if cursor.terminal == nil {
			var err error
			cursor.terminal, err = a.Dataplane.StopMihomoLive(held, cleanup)
			if err != nil {
				return err
			}
		}
		if err := cursor.terminal.ObserveRetired(held, cleanup); err != nil {
			return err
		}
		if cursor.committed == nil {
			resolved := map[string]string{}
			for _, route := range plan.Routes {
				state, ok := cursor.before.AppliedServices[route.LogicalServiceID]
				if !ok || !state.Enabled || selectedRoute(state) != route.Resolved {
					return dataplane.ErrReviewChanged
				}
				resolved[route.LogicalServiceID] = route.Resolved
			}
			for id, state := range cursor.before.AppliedServices {
				if state.Enabled && resolved[id] == "" {
					return dataplane.ErrReviewChanged
				}
			}
			committed, _, err := a.Store.CommitServiceRuntimeWithImage(true, resolved, cursor.before.Revision)
			if err != nil {
				return err
			}
			if committed.Revision != cursor.before.Revision+1 || committed.AppliedRevision != committed.Revision || !committed.ServiceControl.Stopped {
				return config.ErrRevisionChanged
			}
			cursor.committed = &committed
		}
		if !reflect.DeepEqual(a.Store.Get(), *cursor.committed) {
			return config.ErrRevisionChanged
		}
		if _, err := a.Dataplane.CommitRetiredMihomo(held, cursor.terminal, cleanup, cursor.committed.Revision); err != nil {
			return err
		}
		if !reflect.DeepEqual(a.Store.Get(), *cursor.committed) {
			return config.ErrRevisionChanged
		}
		cursor.closing = true
		return cursor.terminal.Close(held, cleanup)
	}()
	if err != nil {
		cursor.context, cursor.release, cursor.cleanup = context.WithoutCancel(held), release, cleanup
		keep = true
		a.Operations.FenceJournal()
		return fail("SERVICE_RUNTIME_FAILED", "Остановка ещё не подтверждена. Исходный владелец сохранён; повторите действие после проверки журнала.")
	}
	completed = true
	a.mihomoProbe.liveStop = nil
	keep = false
	a.wakeReconciler()
	return true, serviceRuntimeOutcome{LiveApplied: true}
}
