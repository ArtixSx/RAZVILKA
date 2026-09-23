package app

import (
	"context"
	"slices"
	"time"
)

func isRuntimeJob(kind string) bool { return kind == "stop" || kind == "resume" }

func validRuntimeJobCode(code string) bool {
	return slices.Contains([]string{"", "SERVICE_RUNTIME_UNAVAILABLE", "SERVICE_CONTROL_CHANGED", "SERVICE_RUNTIME_SAFE_MODE", "SERVICE_RUNTIME_UNCONFIGURED", "SERVICE_RUNTIME_CHANGED", "SERVICE_RUNTIME_CHECK_REQUIRED", "SERVICE_RUNTIME_FAILED"}, code)
}

func runtimeJobMessage(j durableServiceJob) string {
	switch j.State {
	case "queued":
		return "Переключение сохранено на роутере. Дождёмся завершения текущей операции; браузер можно закрыть."
	case "running":
		return "Переключаем маршруты проекта. Панель остаётся доступна."
	case "canceling":
		return "Отмена сохранена. Дожидаемся завершения транзакции и очистки."
	case "interrupted":
		return "После перезапуска проверяем применённое состояние и исходную ревизию."
	case "canceled":
		return "Переключение отменено. Текущее состояние показано отдельно."
	case "completed":
		if j.Request.Kind == "stop" {
			return "Маршруты проекта остановлены. Настройки сохранены; панель доступна."
		}
		return "Сохранённые маршруты включены после проверки. Доступность сервисов показана отдельно."
	}
	switch j.RuntimeCode {
	case "SERVICE_CONTROL_CHANGED", "SERVICE_RUNTIME_CHANGED":
		return "Настройки или применённое состояние изменились. Проверьте текущее состояние: ранее завершённое действие повторно не выполнялось."
	case "SERVICE_RUNTIME_SAFE_MODE":
		return "Безопасный режим запрещает изменение маршрутов. Проверьте настройки безопасности."
	case "SERVICE_RUNTIME_UNCONFIGURED":
		return "Нет подтверждённого маршрута для переключения. Выберите сервис и проверьте подключение."
	case "SERVICE_RUNTIME_CHECK_REQUIRED":
		return "Сохранённое подключение требует проверки. Настройки и ожидающие изменения сохранены."
	}
	if j.CleanupOutcome == "unverified" {
		return "Возврат состояния требует проверки. Следующие изменения приостановлены; откройте журнал."
	}
	return "Переключение не завершено. Откройте журнал и проверьте текущее состояние."
}

func (a *App) hasDueRuntimeStop(now time.Time) bool {
	r := &a.reconciler
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started || r.blocked {
		return false
	}
	for _, j := range r.doc.Jobs {
		if j.Request.Kind == "stop" && (j.State == "queued" || j.State == "interrupted") && !now.Before(j.NotBefore) {
			return true
		}
	}
	return false
}

// Called only after a new Stop has been durably accepted. Invalid requests,
// failed storage and repeated acknowledgements must not interrupt another job.
// Cancellation never releases its admission: transaction cleanup joins first.
func (a *App) preemptForRuntimeStop(acceptedID uint64) {
	r := &a.reconciler
	r.mu.Lock()
	if r.cancel != nil && r.activeJobID != acceptedID {
		r.cancel()
	}
	r.mu.Unlock()
	a.nodeAutofallback.mu.Lock()
	if a.nodeAutofallback.attemptCancel != nil {
		a.nodeAutofallback.attemptCancel()
	}
	a.nodeAutofallback.mu.Unlock()
	a.nodeChecks.mu.Lock()
	if a.nodeChecks.cancel != nil {
		a.nodeChecks.cancel()
	}
	a.nodeChecks.mu.Unlock()
}

func (a *App) runDurableRuntimeJob(ctx context.Context, request serviceControlJobRequest) (serviceRuntimeOutcome, error) {
	release, err := a.Operations.Exclusive(ctx)
	if err != nil {
		return serviceRuntimeOutcome{}, err
	}
	defer func() { release(); a.wakePanelSnapshot() }()
	if err := ctx.Err(); err != nil {
		return serviceRuntimeOutcome{}, err
	}
	return a.executeServiceRuntime(ctx, request.Kind, *request.ExpectedRevision), nil
}
