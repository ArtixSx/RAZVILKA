package app

import (
	"context"
	"errors"
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
	failed map[string]time.Time
}

// Re-checks only an unchanged, already applied node; the check itself changes
// no route. A node that fails stays assigned and keeps blocking the plan.
func (a *App) buildPlanReprovingRetained(ctx context.Context, cfg config.Config, profile string) (dataplane.Plan, error) {
	checked := map[string]bool{}
	for {
		plan, err := a.buildDataplanePlanForScope(cfg, a.nodeRouteOptions(), changeScopeNode, "")
		var dependency *routePlanDependencyError
		if !errors.As(err, &dependency) || !dependency.Retained || dependency.Cause != "check-required" || dependency.NodeID == "" || checked[dependency.ServiceID] || ctx.Err() != nil {
			return plan, err
		}
		checked[dependency.ServiceID] = true
		if a.reproveRetainedNode(ctx, dependency, profile) != nil {
			return plan, err
		}
	}
}

func (a *App) reproveRetainedNode(ctx context.Context, dependency *routePlanDependencyError, profile string) error {
	key := dependency.NodeID + "|" + dependency.ServiceID + "|" + profile
	now := time.Now()
	a.retainedProofs.mu.Lock()
	failedAt, failed := a.retainedProofs.failed[key]
	a.retainedProofs.mu.Unlock()
	if failed && now.Sub(failedAt) < retainedProofRetry {
		return nodestore.ErrRouteProof
	}
	service, ok := a.autonomyService(dependency.ServiceID)
	if !ok {
		return nodestore.ErrRouteProof
	}
	result, _, err := a.checkAndRecordNode(ctx, dependency.NodeID, service, profile, 0)
	if err == nil && !result.Available {
		err = nodestore.ErrRouteProof
	}
	a.retainedProofs.mu.Lock()
	defer a.retainedProofs.mu.Unlock()
	for other, at := range a.retainedProofs.failed {
		if now.Sub(at) >= retainedProofRetry {
			delete(a.retainedProofs.failed, other)
		}
	}
	if err == nil {
		delete(a.retainedProofs.failed, key)
	} else if ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		if a.retainedProofs.failed == nil {
			a.retainedProofs.failed = map[string]time.Time{}
		}
		a.retainedProofs.failed[key] = now
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
		message += "его узел недоступен. Выберите для него другой узел или выключите его."
	} else {
		message += "его узел не прошёл повторную проверку в текущей сети. Проверьте этот узел или выберите другой."
	}
	return "apply-refused", message + " Рабочие маршруты не менялись; попытка повторится.", true
}
