package app

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// The selected node can be healthy while another retained route prevents a
// complete transaction. Expose that dependency, never private node/adapter errors.
type routePlanDependencyError struct {
	ServiceID string
	Name      string
	// NodeID is the exact node whose check would satisfy the plan: the selected
	// node, or the node a group resolved to in the committed plan. It stays
	// server-side; the panel already knows the applied route of the service.
	NodeID string
	// Retained means the same selection is already applied. Checking its node
	// again changes no route, so the panel and autopilot may do it themselves.
	Retained bool
	// "check-required" or "node-unavailable" (missing, disabled or expired).
	Cause string
}

func (e *routePlanDependencyError) Error() string {
	switch {
	case e.Cause == "node-unavailable":
		return "Узел, выбранный для сервиса «" + e.Name + "», недоступен: подписка устарела, узел отключён или удалён. Выберите для сервиса другой узел или NFQWS2 либо выключите сервис, затем повторите применение."
	case e.Retained:
		return "Маршрут сервиса «" + e.Name + "» уже применён, но в текущей сети его узел ещё не проверен. Проверьте подключение этого сервиса, затем повторите применение."
	default:
		return "Нет свежего подтверждения маршрута сервиса «" + e.Name + "». Проверьте его подключение или отдельно измените этот сервис, затем повторите просмотр."
	}
}

func (a *App) routePlanDependency(cfg config.Config, service catalog.Service, selected, committed string) error {
	dependency := &routePlanDependencyError{ServiceID: service.ID, Name: service.Name, Cause: "check-required"}
	node := strings.TrimPrefix(selected, "sing-box:")
	if strings.HasPrefix(node, "group-") {
		node = ""
		if strings.HasPrefix(committed, "sing-box:node-") {
			node = strings.TrimPrefix(committed, "sing-box:")
		}
	}
	applied := cfg.AppliedServices[service.ID]
	dependency.NodeID = node
	dependency.Retained = node != "" && committed != "" && applied.Enabled && selectedRoute(applied) == selected
	if node != "" && a.Nodes != nil {
		now := time.Now()
		if snapshot, err := a.Nodes.Snapshot(context.Background(), now); err == nil && !nodeRecoveryNodePresent(snapshot, node, now) {
			dependency.Cause = "node-unavailable"
		}
	}
	return dependency
}

func writeNodePlanFailure(w http.ResponseWriter, err error) {
	var dependency *routePlanDependencyError
	if errors.As(err, &dependency) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "code": "NODE_ROUTE_DEPENDENCY", "error": dependency.Error(),
			"service_id": dependency.ServiceID, "retained": dependency.Retained,
			"cause": dependency.Cause, "review_required": true,
			"working_routes_changed": false, "live_applied": false,
		})
		return
	}
	if errors.Is(err, dataplane.ErrExactNodeNetworkChanged) {
		writeNodeNetworkError(w)
		return
	}
	writeNodeApplyError(w, "NODE_REVIEW_CHANGED", "План недоступен. Проверьте узел и действующие маршруты, затем повторите просмотр.")
}
