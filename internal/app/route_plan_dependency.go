package app

import (
	"errors"
	"net/http"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// The selected node can be healthy while another retained route prevents a
// complete transaction. Expose that dependency, never private node/adapter errors.
type routePlanDependencyError struct {
	ServiceID string
	Name      string
}

func (e *routePlanDependencyError) Error() string {
	return "Нет свежего подтверждения маршрута сервиса «" + e.Name + "». Проверьте его подключение или отдельно измените этот сервис, затем повторите просмотр."
}

func writeNodePlanFailure(w http.ResponseWriter, err error) {
	var dependency *routePlanDependencyError
	if errors.As(err, &dependency) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "code": "NODE_ROUTE_DEPENDENCY", "error": dependency.Error(),
			"service_id": dependency.ServiceID, "review_required": true,
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
