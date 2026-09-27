package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// CandidateServiceFailure is a negative observation of one HTTPS service path,
// not evidence that the whole node is broken. Only live node health creates it,
// after rechecking the shared runtime. It never authorizes a route on its own.
// No URL, endpoint, response body or credentials are retained in this receipt.
type CandidateServiceFailure struct {
	PlanID      string    `json:"plan_id"`
	Digest      string    `json:"digest"`
	Network     string    `json:"network"`
	ServiceID   string    `json:"service_id"`
	Route       string    `json:"route"`
	RouteDigest string    `json:"route_digest"`
	Code        string    `json:"code"`
	ObservedAt  time.Time `json:"observed_at"`
}

func (e *CandidateServiceFailure) Error() string {
	return "candidate service path rejected the HTTPS check (" + e.Code + ")"
}

func candidateRouteDigest(route Route) string {
	data, _ := json.Marshal(route)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// Matches binds a short-lived in-process failure to the exact transaction and
// route, including device scope and probe definition. Old journals are not
// replay authority; a restarted worker must run fresh checks.
func (e *CandidateServiceFailure) Matches(plan Plan, route Route, now time.Time) bool {
	return e != nil && (e.Code == "http-403" || e.Code == "http-451") &&
		e.PlanID != "" && e.Digest != "" && e.Network != "" &&
		e.PlanID == plan.PlanID && e.Digest == plan.Digest && e.Network == plan.NetworkProfileID &&
		e.ServiceID == route.ServiceID && e.Route == route.Resolved &&
		strings.HasPrefix(route.Resolved, "sing-box:node-") && e.RouteDigest == candidateRouteDigest(route) &&
		!e.ObservedAt.IsZero() && !e.ObservedAt.After(now) && now.Before(e.ObservedAt.Add(2*time.Minute))
}

func (a *ProxyTunnelAdapter) attributeCandidateFailure(ctx context.Context, plan Plan, route Route, state PolicyState, cause error) error {
	var response *serviceResponseError
	if a.ID() != "sing-box" || !strings.HasPrefix(route.Resolved, "sing-box:node-") ||
		!errors.As(cause, &response) || (response.code != "http-403" && response.code != "http-451") {
		return cause
	}
	// Loss of common processes, forwarding, policy or review authority must not
	// penalize the candidate even when it coincides with a definite HTTP reply.
	if err := a.checkPlanNetwork(ctx, plan); err != nil {
		return err
	}
	if err := a.verifyHealthRuntime(ctx, state); err != nil {
		return err
	}
	if err := a.checkPlanNetwork(ctx, plan); err != nil {
		return err
	}
	return &CandidateServiceFailure{PlanID: plan.PlanID, Digest: plan.Digest,
		Network: plan.NetworkProfileID, ServiceID: route.ServiceID, Route: route.Resolved,
		RouteDigest: candidateRouteDigest(route), Code: response.code, ObservedAt: time.Now().UTC()}
}
