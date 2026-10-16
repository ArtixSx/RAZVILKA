package app

import (
	"context"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

// This retains the actual invocation's resources, never a serialized proof or
// an alternate journal. Only its original completion can retire the lease.
type strategyCompatibilityRetention struct {
	manager    *strategylab.Manager
	components *components.Manager
	runtime    *components.ManagedNFQWSRuntimeLease
	completion *strategylab.ManagedCompatibilityCompletion
	release    func()
}

type strategyCompatibilityState struct {
	mu      sync.Mutex
	pending *strategyCompatibilityRetention
}

func (a *App) strategyCompatibilityPending() bool {
	a.strategyCompatibility.mu.Lock()
	defer a.strategyCompatibility.mu.Unlock()
	return a.strategyCompatibility.pending != nil && a.strategyCompatibility.pending.release != nil
}

// WaitManagedStrategyCompatibility retries only the actual retained producer's
// cleanup during shutdown. A successful retirement releases the original
// operation once; its recovery fence and readonly diagnostic view remain.
// No new validation, forward context or replacement owner is constructed.
func (a *App) WaitManagedStrategyCompatibility(ctx context.Context) error {
	a.strategyCompatibility.mu.Lock()
	defer a.strategyCompatibility.mu.Unlock()
	held := a.strategyCompatibility.pending
	if held == nil || held.release == nil {
		return nil
	}
	if held.completion == nil {
		return strategylab.ErrCompatibilityQuiescenceUnknown
	}
	if err := held.completion.RetireKnown(ctx); err != nil {
		return err
	}
	held.release()
	held.release = nil
	return nil
}

func (a *App) retainStrategyCompatibility(held *strategyCompatibilityRetention) {
	a.strategyCompatibility.mu.Lock()
	defer a.strategyCompatibility.mu.Unlock()
	// The actual original exclusive admission excludes another invocation.
	// Neither request cancellation nor a timer releases these resources.
	a.strategyCompatibility.pending = held
	a.Operations.FenceJournal()
}

func writeStrategyCompatibilityRecovery(w http.ResponseWriter, notStarted bool) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{
		"ok": false, "code": "STRATEGY_COMPATIBILITY_RECOVERY_REQUIRED",
		"error":       "Завершение проверки NFQWS2 требует проверки сохранённой операции. Изменения приостановлены; повторный запуск автоматически не выполняется.",
		"not_started": notStarted, "live_applied": false, "recovery_required": true,
		"name": "RAZVILKA", "version": Version, "process_id": os.Getpid(),
	})
}

func (a *App) validateStrategyCandidate(w http.ResponseWriter, ctx context.Context, id string, release func()) {
	owned := true
	defer func() {
		if owned {
			release()
		}
	}()
	if a.Components == nil {
		// Embedders without the production component owner retain the existing
		// library validator. Ordinary main always has its configured Components.
		candidate, err := a.StrategyLab.Validate(ctx, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, candidate)
		return
	}
	acquireCtx, finishAcquire := context.WithTimeout(ctx, strategylab.ManagedCompatibilityAcquisitionTimeout)
	lease, err := a.Components.AcquireCurrentManagedNFQWSRuntime(acquireCtx)
	finishAcquire() // The concrete lease retains no acquisition context.
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "code": "MANAGED_NFQWS_SOURCE_UNAVAILABLE",
			"error":       "Установленный управляемый NFQWS2 недоступен для проверки совместимости.",
			"not_started": true, "live_applied": false,
		})
		return
	}
	held := &strategyCompatibilityRetention{manager: a.StrategyLab, components: a.Components, runtime: lease, release: release}
	candidate, completion, validationErr := held.manager.ValidateManagedCandidate(ctx, id, lease)
	held.completion = completion
	var retireErr error
	if completion == nil {
		// The concrete producer guarantees nil only before any invocation or
		// provider intent/effect; the original lease remains caller-owned.
		retireErr = lease.Close()
	} else {
		cleanupCtx, finish := context.WithTimeout(context.Background(), 5*time.Second)
		retireErr = completion.RetireKnown(cleanupCtx)
		finish()
	}
	if retireErr != nil {
		a.retainStrategyCompatibility(held)
		owned = false
		writeStrategyCompatibilityRecovery(w, completion == nil)
		return
	}
	if validationErr != nil {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "code": "STRATEGY_COMPATIBILITY_REFUSED",
			"error":       "Проверка совместимости NFQWS2 отклонена. Сохранённые данные требуют повторной проверки перед применением.",
			"not_started": completion == nil, "live_applied": false,
		})
		return
	}
	if completion == nil {
		// A nil completion can never be success, even if a future producer
		// accidentally returns an empty error with its pre-admission refusal.
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "code": "STRATEGY_COMPATIBILITY_REFUSED", "live_applied": false})
		return
	}
	writeJSON(w, http.StatusOK, candidate)
}
