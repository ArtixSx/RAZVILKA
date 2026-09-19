package app

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Keep the transaction result with its cause. In particular, rolled-back is
// not permission to continue: Execution identifies an adapter/phase, but not
// the failed service/node or whether a shared engine caused the failure.
// Never derive attribution by matching the diagnostic error text.
type autonomyApplyFailure struct {
	Execution dataplane.Execution
	Cause     error
}

func (e *autonomyApplyFailure) Error() string { return "autonomous application was not confirmed" }
func (e *autonomyApplyFailure) Unwrap() error { return e.Cause }

func (a *App) checkAutonomyReserve(ctx context.Context, p autonomy.Policy, s autonomy.Service, base config.Config, id string, service catalog.Service, profile string) (dataplane.NodeCheckResult, error) {
	guard := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !reflect.DeepEqual(a.Store.Get(), base) || !a.autonomyConsent(p, s) || a.autonomyDiskCurrent(ctx) != nil {
			return dataplane.ErrReviewChanged
		}
		latest, ok := a.autonomyService(s.ID)
		if !ok || autonomyDefinition(latest) != s.Definition {
			return dataplane.ErrReviewChanged
		}
		return nil
	}
	if err := guard(); err != nil {
		return dataplane.NodeCheckResult{}, err
	}
	result, _, err := a.checkAndRecordNode(ctx, id, service, profile, 0)
	if err == nil {
		err = guard()
	}
	return result, err
}

func autonomyApplyFailureStatus(err error) (string, string) {
	var failure *autonomyApplyFailure
	if errors.As(err, &failure) && failure.Execution.State == "rollback-failed" {
		return "requires-review", "Возврат прежнего состояния не завершён. Новые проверки и переключения остановлены."
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, dataplane.ErrReviewChanged) {
		return "paused", "Применение отменено: разрешения или условия проверки изменились."
	}
	if errors.Is(err, dataplane.ErrNetworkChanged) {
		return "network-unknown", "Сеть изменилась или не подтверждена. Переключение отложено."
	}
	return "apply-refused", "Изменение не подтверждено. Сохранены защитные проверки и откат."
}

// Only a fresh, attributed FAIL permits checking the next reserve. An
// incomplete check, a common control failure or a cleanup problem cannot be
// converted to a negative reputation for the candidate.
func autonomyReserveCheckStop(ctx context.Context, result dataplane.NodeCheckResult, err error) (string, string) {
	// Cleanup failure must survive a simultaneous cancellation/network change.
	if result.ErrorCode == "node-cleanup-failed" {
		return "requires-review", "Очистка временной проверки не завершена. Следующие проверки и переключения остановлены."
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, dataplane.ErrReviewChanged) {
		return "paused", "Проверка отменена или её условия изменились; рабочий маршрут не меняется."
	}
	if errors.Is(err, dataplane.ErrExactNodeNetworkChanged) || errors.Is(err, dataplane.ErrNetworkChanged) {
		return "network-unknown", "Текущая сеть не подтверждена. Проверка резерва отложена."
	}
	if err != nil {
		return "checker-unavailable", "Механизм проверки недоступен. Узел не признан неисправным; подбор приостановлен."
	}
	if autonomyNodeObservation(result, time.Now()) == "INCONCLUSIVE" {
		return "unconfirmed", "Проверка резерва не дала определённого результата. Прежний маршрут сохранён; подбор повторится позже."
	}
	return "", ""
}
