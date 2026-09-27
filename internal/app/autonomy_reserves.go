package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Keep the exact attempted plan and transaction result with their typed cause.
// rolled-back alone never grants permission to continue.
type autonomyApplyFailure struct {
	Plan      dataplane.Plan
	Execution dataplane.Execution
	Cause     error
}

func (e *autonomyApplyFailure) Error() string { return "autonomous application was not confirmed" }
func (e *autonomyApplyFailure) Unwrap() error { return e.Cause }

// Accept only a definite candidate service rejection during live Health,
// followed by verified rollback of every adapter and an unchanged config.
// The caller holds the same exclusive operation throughout B -> rollback -> C.
func (a *App) autonomyCandidateFailure(ctx context.Context, p autonomy.Policy, s autonomy.Service, base config.Config, profile, id string, err error) (autonomy.CandidateFailure, bool) {
	var failed *autonomyApplyFailure
	var cause *dataplane.CandidateServiceFailure
	if ctx.Err() != nil || !errors.As(err, &failed) || !errors.As(err, &cause) ||
		errors.Is(err, dataplane.ErrNetworkChanged) || errors.Is(err, dataplane.ErrReviewChanged) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		failed.Execution.State != "rolled-back" || !failed.Execution.RollbackVerified ||
		failed.Execution.PlanID != failed.Plan.PlanID || failed.Execution.Digest != failed.Plan.Digest ||
		failed.Plan.NetworkProfileID != profile || !reflect.DeepEqual(a.Store.Get(), base) ||
		!a.autonomyConsent(p, s) || a.autonomyDiskCurrent(ctx) != nil {
		return autonomy.CandidateFailure{}, false
	}
	failures := 0
	for _, step := range failed.Execution.Steps {
		if step.State == "failed" {
			if step.Adapter != "sing-box" || step.Phase != "health" {
				return autonomy.CandidateFailure{}, false
			}
			failures++
		}
	}
	if failures != 1 {
		return autonomy.CandidateFailure{}, false
	}
	status, statusErr := a.Dataplane.Status()
	if statusErr != nil || status.Execution == nil || !reflect.DeepEqual(*status.Execution, failed.Execution) {
		return autonomy.CandidateFailure{}, false
	}
	service, ok := a.autonomyService(s.ID)
	if !ok || autonomyDefinition(service) != s.Definition {
		return autonomy.CandidateFailure{}, false
	}
	observed, networkErr := a.freshNetworkProfile(ctx)
	if networkErr != nil || observed != profile {
		return autonomy.CandidateFailure{}, false
	}
	for _, route := range failed.Plan.Routes {
		if route.ServiceID == s.ID && route.Resolved == "sing-box:"+id &&
			sameNodeRecoveryStrings(route.Sources, s.Sources) && nodeRecoveryServiceMatches(route, service) &&
			cause.Matches(failed.Plan, route, time.Now()) {
			return autonomy.CandidateFailure{NodeID: strings.TrimPrefix(route.Resolved, "sing-box:"),
				Network: profile, Definition: s.Definition, Scope: autonomy.ScopeFingerprint(s.Sources),
				PlanID: failed.Plan.PlanID, Code: cause.Code, ObservedAt: cause.ObservedAt}, true
		}
	}
	return autonomy.CandidateFailure{}, false
}

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
