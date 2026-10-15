package app

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// A failed re-check of an applied node is not repeated by every service round.
const retainedProofRetry = 10 * time.Minute

// Every plan carries all enabled routes, including a node route the user
// applied earlier. Its exact proof expires after 30 minutes and with every
// network epoch, so an unrelated autopilot apply would otherwise stop at it.
type retainedProofState struct {
	mu     sync.Mutex
	failed map[string]retainedProofFailure
}

// Closed diagnostic vocabulary only; no checker message, endpoint or raw
// transport error is copied into a dependency, API response or runtime log.
type retainedProofFailure struct {
	At         time.Time
	Stage      string
	Code       string
	HTTPStatus int
	cause      error
}

func (retainedProofFailure) Error() string   { return "retained node reproof refused" }
func (f retainedProofFailure) Unwrap() error { return f.cause }

func retainedReproofFailure(result dataplane.NodeCheckResult, err error, now time.Time) retainedProofFailure {
	f := retainedProofFailure{At: now, Stage: "check", Code: "node-check-unconfirmed", cause: err}
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			f.Stage, f.Code = "canceled", "check-canceled"
		case errors.Is(err, context.DeadlineExceeded):
			f.Stage, f.Code = "canceled", "check-timeout"
		case errors.Is(err, dataplane.ErrExactNodeNetworkChanged):
			f.Code = "network-changed"
		case errors.Is(err, dataplane.ErrNodeResourceDenied):
			f.Code = "resource-refused"
		}
		return f
	}
	if slices.Contains([]string{"dns", "transport", "configuration", "protocol", "route_identity", "egress", "service", "service_ip", "cleanup"}, result.Stage) {
		f.Stage = result.Stage
	}
	if slices.Contains([]string{"node-config-invalid", "node-dns-failed", "node-transport-failed", "node-runtime-config-rejected", "node-protocol-start-failed", "node-route-runtime-changed", "node-route-identity-failed", "node-egress-control-unavailable", "node-egress-failed", "node-direct-leak", "node-direct-control-unavailable", "node-service-probe-failed", "node-service-ip-unavailable", "node-service-ip-path-failed", "node-route-mismatch", "node-service-not-confirmed", "http-403", "http-429", "http-451", "tls-certificate-mismatch", "route-identity-mismatch"}, result.ErrorCode) {
		f.Code = result.ErrorCode
	}
	if result.HTTPStatus >= 100 && result.HTTPStatus <= 599 {
		f.HTTPStatus = result.HTTPStatus
	}
	// A later literal-IP check replaces Evidence, while HTTPStatus can still
	// contain the earlier domain request's response.
	if result.Stage == "service_ip" && result.Evidence.HTTPStatus >= 100 && result.Evidence.HTTPStatus <= 599 {
		f.HTTPStatus = result.Evidence.HTTPStatus
	}
	return f
}

// Re-checks only an unchanged, already applied node; the check itself changes
// no route. A node that fails stays assigned and keeps blocking the plan.
func (a *App) buildPlanReprovingRetained(ctx context.Context, cfg config.Config, profile string) (dataplane.Plan, error) {
	checked := map[string]bool{}
	for {
		plan, err := a.buildDataplanePlanForScopeContext(ctx, cfg, a.nodeRouteOptions(), changeScopeNode, "")
		var dependency *routePlanDependencyError
		if !errors.As(err, &dependency) || !dependency.Retained || dependency.Cause != "check-required" || dependency.NodeID == "" || checked[dependency.ServiceID] || ctx.Err() != nil {
			return plan, err
		}
		checked[dependency.ServiceID] = true
		if reproofErr := a.reproveRetainedNode(ctx, dependency, profile); reproofErr != nil {
			failure := retainedReproofFailure(dataplane.NodeCheckResult{}, reproofErr, time.Now())
			_ = errors.As(reproofErr, &failure)
			copy := *dependency
			copy.Cause, copy.CheckStage, copy.CheckCode, copy.HTTPStatus = "reproof-failed", failure.Stage, failure.Code, failure.HTTPStatus
			return plan, &copy
		}
	}
}

func (a *App) reproveRetainedNode(ctx context.Context, dependency *routePlanDependencyError, profile string) error {
	engine, engineErr := nodeCheckEngine(dependency.Engine)
	if engineErr != nil {
		return nodestore.ErrRouteProof
	}
	key := engine + "|" + dependency.NodeID + "|" + dependency.ServiceID + "|" + profile
	now := time.Now()
	a.retainedProofs.mu.Lock()
	failure, failed := a.retainedProofs.failed[key]
	a.retainedProofs.mu.Unlock()
	if failed && now.Sub(failure.At) < retainedProofRetry {
		return failure
	}
	service, ok := a.autonomyService(dependency.ServiceID)
	if !ok {
		return nodestore.ErrRouteProof
	}
	result, _, err := a.checkAndRecordNodeForEngine(ctx, engine, dependency.NodeID, service, profile, 0)
	if err != nil || !result.Available {
		err = retainedReproofFailure(result, err, now)
	}
	a.retainedProofs.mu.Lock()
	defer a.retainedProofs.mu.Unlock()
	for other, failure := range a.retainedProofs.failed {
		if now.Sub(failure.At) >= retainedProofRetry {
			delete(a.retainedProofs.failed, other)
		}
	}
	if err == nil {
		delete(a.retainedProofs.failed, key)
	} else if ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		if a.retainedProofs.failed == nil {
			a.retainedProofs.failed = map[string]retainedProofFailure{}
		}
		var failure retainedProofFailure
		if errors.As(err, &failure) {
			a.retainedProofs.failed[key] = failure
		}
	}
	return err
}

// Nothing was activated when another service's route blocked the plan, so the
// switch reservation is returned and the runtime names the blocking service.
func autonomyRouteDependency(err error, r *autonomy.Runtime) (string, string, bool) {
	var dependency *routePlanDependencyError
	if !errors.As(err, &dependency) {
		return "", "", false
	}
	r.RefundSwitch()
	message := "Применение ждёт сервис «" + dependency.Name + "»: "
	if dependency.Cause == "node-unavailable" {
		message += "его узел недоступен. Сервисы из списка NFQWS2 автопилот сам вернёт на штатный NFQWS2; для остальных выберите другой узел или NFQWS2 либо выключите сервис."
	} else if dependency.Cause == "reproof-failed" {
		message += dependency.reproofDescription() + " Проверьте этот узел или выберите другой."
	} else {
		message += "его узел не прошёл повторную проверку в текущей сети. Проверьте этот узел или выберите другой."
	}
	return "apply-refused", message + " Рабочие маршруты не менялись; попытка повторится.", true
}
