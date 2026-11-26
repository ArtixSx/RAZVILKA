package dataplane

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// CandidateCanaryTimeout is an ephemeral rejection of an isolated Xray
// candidate. Its zero value, copied value and journal text grant nothing.
// It records no negative observation of the node or its source.
type CandidateCanaryTimeout struct {
	self           *CandidateCanaryTimeout
	routes         []byte
	route          []byte
	observed       time.Time
	cleaned        bool
	manager        *Manager
	execution      []byte
	previous       []byte
	previousExists bool
}

func (*CandidateCanaryTimeout) Error() string {
	return "isolated Xray candidate service path timed out"
}

// Only the literal service probe produces this error. Cleanup and Manager
// publication must independently close before Matches can return true.
func candidateCanaryTimeout(plan RoutePlan, route Route, cause error) error {
	failure, ok := cause.(nodeIPProbeFailure)
	if !ok || failure.reason != nodeIPTimeout || plan.Adapter != "xray" ||
		!strings.HasPrefix(route.Resolved, "xray:node-") || len(route.Domains) != 0 || len(route.CIDRs) == 0 {
		return cause
	}
	// Freeze complete canonical images and compare them in the same encoding.
	// Never decode back into a RoutePlan: omitempty would change nil versus
	// present-empty fields and reject legitimate unchanged Manager images.
	routes, err := json.Marshal(plan)
	if err != nil {
		return cause
	}
	selected, err := json.Marshal(route)
	if err != nil {
		return cause
	}
	f := &CandidateCanaryTimeout{routes: routes, route: selected, observed: time.Now().UTC()}
	f.self = f
	return f
}

// A joined error is acceptable only when every leaf is the SAME error. Any
// journal, scope-close, cleanup or cancellation error prevents certification.
func soleCanaryTimeout(err error) *CandidateCanaryTimeout {
	if f, ok := err.(*CandidateCanaryTimeout); ok && f != nil && f.self == f {
		return f
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var found *CandidateCanaryTimeout
		for _, child := range joined.Unwrap() {
			f := soleCanaryTimeout(child)
			if f == nil || found != nil && found != f {
				return nil
			}
			found = f
		}
		return found
	}
	return nil
}

// ExactCandidateCanaryTimeout refuses mixed error trees. It exposes an
// existing live certificate, never constructs one from text or fields.
func ExactCandidateCanaryTimeout(err error) *CandidateCanaryTimeout { return soleCanaryTimeout(err) }

func canaryImageEqual(image []byte, value any) bool {
	data, err := json.Marshal(value)
	return err == nil && string(data) == string(image)
}

func (f *CandidateCanaryTimeout) seal(m *Manager, p Plan, x Execution, previous Plan, exists bool) {
	if f == nil || f.self != f || !f.cleaned || !canaryImageEqual(f.routes, p.RoutePlanFor("xray")) ||
		x.State != "canary-failed" || x.PlanID != p.PlanID || x.Digest != p.Digest || len(x.Resources) != 0 || validateExecutionResources(x, true) != nil {
		return
	}
	failures := 0
	for _, step := range x.Steps {
		if step.Phase != "snapshot" && step.Phase != "stage" && step.Phase != "validate" && step.Phase != "canary" {
			return
		}
		if step.State == "failed" {
			if step.Adapter != "xray" || step.Phase != "canary" {
				return
			}
			failures++
		} else if step.State != "passed" {
			return
		}
	}
	if failures != 1 {
		return
	}
	f.execution, _ = json.Marshal(x)
	f.previous, _ = json.Marshal(previous)
	f.previousExists, f.manager = exists, m
}

// Matches reopens the same Manager's journals; durable data can confirm this
// live error, but cannot recreate it after restart or select another attempt.
func (f *CandidateCanaryTimeout) Matches(ctx context.Context, m *Manager, p Plan, x Execution, route Route, now time.Time) bool {
	if f == nil || f.self != f || !f.cleaned || f.manager != m || m == nil || ctx == nil || ctx.Err() != nil ||
		f.observed.IsZero() || f.observed.After(now) || !now.Before(f.observed.Add(2*time.Minute)) ||
		!canaryImageEqual(f.routes, p.RoutePlanFor("xray")) || !canaryImageEqual(f.route, route) {
		return false
	}
	raw, err := json.Marshal(x)
	if err != nil || string(raw) != string(f.execution) {
		return false
	}
	status, err := m.Status()
	if err != nil || status.Execution == nil || !canaryImageEqual(f.execution, *status.Execution) {
		return false
	}
	previous, exists, err := m.Committed()
	if err != nil || exists != f.previousExists {
		return false
	}
	raw, err = json.Marshal(previous)
	return err == nil && string(raw) == string(f.previous) && ctx.Err() == nil
}
