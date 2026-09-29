package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
)

func TestAutopilotPlanReprovesRetainedNodeRoute(t *testing.T) {
	a, id, adapter, checker, _ := nodeRecoveryFixture(t)
	cfg := a.Store.Get()
	_, err := a.buildDataplanePlanForScope(cfg, a.nodeRouteOptions(), changeScopeNode, "")
	var dependency *routePlanDependencyError
	if !errors.As(err, &dependency) || !dependency.Retained || dependency.NodeID != id || dependency.Cause != "check-required" || !strings.Contains(dependency.Error(), "Telegram") {
		t.Fatalf("retained route not identified: %#v", err)
	}
	plan, err := a.buildPlanReprovingRetained(context.Background(), cfg, recoveryProfile)
	// The fixture's unrelated draft may block the plan; the retained route must not.
	if err != nil || plan.NetworkProfileID != recoveryProfile || len(plan.Routes) == 0 || plan.Routes[0].ServiceID != "telegram" || plan.Routes[0].Resolved != "sing-box:"+id {
		t.Fatalf("routes=%+v err=%v", plan.Routes, err)
	}
	if len(checker.requests) != 1 || checker.requests[0].NodeID != id || checker.requests[0].Service.ID != "telegram" || checker.requests[0].NetworkProfile != recoveryProfile {
		t.Fatalf("checked different target: %+v", checker.requests)
	}
	if len(adapter.calls) != 0 || !reflect.DeepEqual(cfg, a.Store.Get()) {
		t.Fatal("re-proof changed routes or configuration")
	}
}

func TestAutopilotRetainedNodeFailureIsRememberedAndNamed(t *testing.T) {
	a, _, adapter, checker, _ := nodeRecoveryFixture(t)
	checker.fail = true
	cfg := a.Store.Get()
	var err error
	for range 2 {
		_, err = a.buildPlanReprovingRetained(context.Background(), cfg, recoveryProfile)
		var dependency *routePlanDependencyError
		if !errors.As(err, &dependency) || dependency.ServiceID != "telegram" {
			t.Fatalf("dependency lost: %v", err)
		}
	}
	if len(checker.requests) != 1 || len(adapter.calls) != 0 {
		t.Fatalf("failed node re-checked every round: %d", len(checker.requests))
	}
	r := autonomy.Runtime{Switches: []time.Time{time.Now().Add(-time.Minute), time.Now()}}
	state, message, blocked := autonomyRouteDependency(err, &r)
	if !blocked || state != "apply-refused" || len(r.Switches) != 1 || !strings.Contains(message, "«Telegram»") {
		t.Fatalf("state=%q message=%q switches=%d", state, message, len(r.Switches))
	}
	if _, _, blocked := autonomyRouteDependency(errors.New("other"), &r); blocked || len(r.Switches) != 1 {
		t.Fatal("unrelated failure refunded a switch")
	}
}

func TestPlanDependencyReportsUnavailableRetainedNode(t *testing.T) {
	a, id, _, checker, _ := nodeRecoveryFixture(t)
	if _, err := a.Nodes.SetDisabled(context.Background(), id, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, err := a.buildPlanReprovingRetained(context.Background(), a.Store.Get(), recoveryProfile)
	var dependency *routePlanDependencyError
	if !errors.As(err, &dependency) || dependency.Cause != "node-unavailable" || len(checker.requests) != 0 || strings.Contains(dependency.Error(), id) {
		t.Fatalf("unavailable node: %#v checks=%d", err, len(checker.requests))
	}
}
