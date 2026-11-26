package dataplane

import (
	"context"
	"encoding/json"
	"time"
)

// This holder exists only for an exact USQUE canary transport launched with
// StartOriginal. An adapter without original child custody issues no proof.
type usqueCanaryAttemptKey struct{}

type usqueCanaryAttempt struct {
	adapter *ProxyTunnelAdapter
	joined  *OriginalProcess
}

// This in-memory error acquires meaning only when the original Manager seals
// its exact failed execution after publishing the completed journals.
type usqueCanaryRejection struct {
	self           *usqueCanaryRejection
	adapter        *ProxyTunnelAdapter
	manager        *Manager
	review         context.Context
	routes         []byte
	execution      []byte
	previous       []byte
	previousExists bool
	joined         [2]*OriginalProcess
	observed       time.Time
	message        string
}

func (r *usqueCanaryRejection) Error() string { return r.message }

func newUSQUECanaryRejection(adapter *ProxyTunnelAdapter, plan RoutePlan, joined []*OriginalProcess, cause error) *usqueCanaryRejection {
	if len(joined) != 2 || joined[0] == nil || joined[1] == nil || joined[0] == joined[1] || plan.Adapter != "usque" {
		return nil
	}
	first, firstErr := ownedUSQUECandidateTransport(joined[0].spec, joined[0].endpoint)
	second, secondErr := ownedUSQUECandidateTransport(joined[1].spec, joined[1].endpoint)
	if firstErr != nil || secondErr != nil || first == second || joined[0].endpoint != joined[1].endpoint {
		return nil
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil
	}
	r := &usqueCanaryRejection{adapter: adapter, routes: encoded, joined: [2]*OriginalProcess{joined[0], joined[1]}, observed: time.Now(), message: cause.Error()}
	r.self = r
	return r
}

// A journal, closing guard or cleanup error cannot borrow a joined proof.
func soleUSQUECanaryRejection(err error, depth int) *usqueCanaryRejection {
	if r, ok := err.(*usqueCanaryRejection); ok && r != nil && r.self == r {
		return r
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok && depth > 0 {
		causes := joined.Unwrap()
		if len(causes) == 1 {
			return soleUSQUECanaryRejection(causes[0], depth-1)
		}
	}
	return nil
}

func (r *usqueCanaryRejection) seal(ctx context.Context, m *Manager, adapter Adapter, plan Plan, execution Execution, previous Plan, exists bool) bool {
	current, _ := m.adapter("usque")
	if current != r.adapter || adapter != r.adapter || !canaryImageEqual(r.routes, plan.RoutePlanFor("usque")) ||
		execution.State != "canary-failed" || execution.PlanID != plan.PlanID || execution.Digest != plan.Digest ||
		execution.StartedAt == "" || execution.FinishedAt == "" || execution.ResourcePlanID != "" || len(execution.Resources) != 0 || execution.RollbackVerified {
		return false
	}
	if len(execution.Steps) == 0 {
		return false
	}
	for i, step := range execution.Steps {
		if step.StartedAt == "" || step.FinishedAt == "" {
			return false
		}
		if i == len(execution.Steps)-1 {
			if step.Adapter != "usque" || step.Phase != "canary" || step.State != "failed" {
				return false
			}
			continue
		}
		switch step.Phase {
		case "snapshot", "stage", "validate", "canary":
			if step.State != "passed" {
				return false
			}
		default:
			return false
		}
	}
	x, executionErr := json.Marshal(execution)
	p, previousErr := json.Marshal(previous)
	if executionErr != nil || previousErr != nil {
		return false
	}
	r.execution, r.previous, r.previousExists, r.manager, r.review = x, p, exists, m, ctx
	return true
}

// ConfirmedUSQUECanaryRejection reads the same Manager's current journals and
// the owned canary listener. A serialized execution, copied error, or generic
// adapter failure cannot supply the original two joined child observations.
func ConfirmedUSQUECanaryRejection(ctx context.Context, m *Manager, plan Plan, execution Execution, err error) bool {
	r := soleUSQUECanaryRejection(err, 16)
	if r == nil || ctx == nil || ctx.Err() != nil || m == nil || r.manager != m ||
		time.Since(r.observed) < 0 || time.Since(r.observed) >= 2*time.Minute ||
		!canaryImageEqual(r.routes, plan.RoutePlanFor("usque")) || !canaryImageEqual(r.execution, execution) {
		return false
	}
	current, _ := m.adapter("usque")
	if current != r.adapter || originalProcessListenerAbsent(ctx, r.joined[1].port) != nil {
		return false
	}
	status, readErr := m.Status()
	if readErr != nil || status.Execution == nil || !canaryImageEqual(r.execution, *status.Execution) ||
		(status.CommittedPlan != nil) != r.previousExists || (r.previousExists && !canaryImageEqual(r.previous, *status.CommittedPlan)) {
		return false
	}
	return r.review != nil && r.review.Err() == nil && m.checkPlanNetwork(r.review, plan) == nil && r.review.Err() == nil && ctx.Err() == nil
}
