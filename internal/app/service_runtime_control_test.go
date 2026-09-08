package app

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

type serviceRuntimeAdapter struct {
	*nodeApplyAdapter
	name string
}

func (a *serviceRuntimeAdapter) ID() string                       { return a.name }
func (a *serviceRuntimeAdapter) Deactivate(context.Context) error { return a.phase("deactivate") }

func serviceRuntimeFixture(t *testing.T) (*App, string, *serviceRuntimeAdapter, config.Config) {
	t.Helper()
	a, id, adapter := nodeApplyFixture(t)
	owned := &serviceRuntimeAdapter{nodeApplyAdapter: adapter, name: "sing-box"}
	// Install the fake before serving requests; the runtime tests still use
	// the real Manager transaction/rollback and config disk CAS.
	a.Dataplane.Adapters["sing-box"] = owned
	review := reviewedNode(t, a, id)
	if w := nodeRouteRequest(a, id, "apply", nodeApplyBody(review), "owner-a", context.Background()); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	adapter.calls = nil
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return autofallbackResult(request, true), nil
	})
	a.EngineConfigs = engineconfig.New(filepath.Join(t.TempDir(), "staged"), t.TempDir())
	if _, err := a.EngineConfigs.Stage("sing-box", "main", `{"log":{"level":"debug"}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := a.EngineConfigs.Stage("nfqws2", "user-list", "pending.example\n"); err != nil {
		t.Fatal(err)
	}
	return a, id, owned, a.Store.Get()
}

func runtimeRequest(a *App, action string) *httptest.ResponseRecorder {
	confirm := "STOP_OWNED_ROUTES"
	if action == "resume" {
		confirm = "RESUME_OWNED_ROUTES"
	}
	return controlRequest(a, "POST", "/api/v1/service-control/runtime", map[string]any{"action": action, "expected_revision": a.Store.Get().Revision, "confirm": confirm})
}

func TestServiceRuntimeStopResumeExactScopePreservesPendingAndUnownedAdapters(t *testing.T) {
	a, _, adapter, before := serviceRuntimeFixture(t)
	other := &serviceRuntimeAdapter{nodeApplyAdapter: &nodeApplyAdapter{}, name: "warp-wg"}
	if err := a.Dataplane.Register(other); err != nil {
		t.Fatal(err)
	}
	view := a.serviceControlView()
	if view["runtime_state"] != "unknown" || view["can_stop"] != true || view["running"] != false {
		t.Fatal("committed journal falsely proved live fake runtime")
	}
	if w := runtimeRequest(a, "stop"); w.Code != 200 {
		t.Fatalf("stop: %d %s", w.Code, w.Body.String())
	}
	stopped := a.Store.Get()
	if !stopped.ServiceControl.Stopped || len(stopped.AppliedServices) != 0 || !reflect.DeepEqual(before.Services, stopped.Services) || !reflect.DeepEqual(before.AppliedServices, stopped.ServiceControl.SuspendedServices) || len(other.calls) != 0 {
		t.Fatal("stop affected pending/unowned routes")
	}
	if strings.Join(adapter.calls, ",") != "snapshot,deactivate" {
		t.Fatalf("stop bypassed owned retirement: %v", adapter.calls)
	}
	a.nodeRecoveryRound(context.Background(), time.Now().Add(time.Minute))
	a.nodeAutofallbackRound(context.Background(), time.Now().Add(time.Minute))
	if len(adapter.calls) != 2 {
		t.Fatal("stopped route restarted automatically")
	}
	if w := runtimeRequest(a, "resume"); w.Code != 200 {
		t.Fatalf("resume: %d %s", w.Code, w.Body.String())
	}
	after := a.Store.Get()
	if after.ServiceControl.Stopped || !reflect.DeepEqual(after.Services, before.Services) || !reflect.DeepEqual(after.AppliedServices, before.AppliedServices) || !reflect.DeepEqual(after.ServicePolicies, before.ServicePolicies) || len(other.calls) != 0 {
		t.Fatal("resume widened or lost saved state")
	}
	plan, _, _ := a.Dataplane.Committed()
	if len(plan.EngineDrafts) != 0 || len(plan.Routes) != 1 || !reflect.DeepEqual(plan.Routes[0].Sources, before.AppliedServices["telegram"].Sources) {
		t.Fatal("resume consumed pending scope/engine file")
	}
	for _, ref := range [][2]string{{"sing-box", "main"}, {"nfqws2", "user-list"}} {
		file, err := a.EngineConfigs.ReadExpert(ref[0], ref[1])
		if err != nil || file.Source != "staged" {
			t.Fatal("power cycle consumed editor changes")
		}
	}
}

func TestServiceRuntimeFailureAndFreshProofRefusalPreserveSnapshot(t *testing.T) {
	for _, phase := range []string{"deactivate", "resume-check", "resume-health"} {
		t.Run(phase, func(t *testing.T) {
			a, _, adapter, before := serviceRuntimeFixture(t)
			if phase == "deactivate" {
				adapter.after = func(p string) error {
					if p == "deactivate" {
						return errors.New("simulated owned stop failure")
					}
					return nil
				}
			}
			w := runtimeRequest(a, "stop")
			if phase == "deactivate" {
				if w.Code != 409 || !reflect.DeepEqual(before, a.Store.Get()) || !strings.Contains(strings.Join(adapter.calls, ","), "rollback") {
					t.Fatal("stop failure not rolled back", w.Body.String())
				}
				return
			}
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			before = a.Store.Get()
			if phase == "resume-check" {
				a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
					return autofallbackResult(request, false), nil
				})
			}
			if phase == "resume-health" {
				adapter.after = func(p string) error {
					if p == "health" {
						return errors.New("simulated unhealthy runtime")
					}
					return nil
				}
			}
			w = runtimeRequest(a, "resume")
			if w.Code != 409 || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("failed resume lost snapshot", w.Body.String())
			}
		})
	}
}

func TestServiceRuntimeUnconfiguredDoesNotApplyPending(t *testing.T) {
	a, _ := serviceControlFixture(t, 1)
	a.Dataplane = dataplane.New(t.TempDir())
	_ = a.Store.SetSafeMode(false)
	_ = a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "auto", Sources: []string{"192.168.1.40/32"}})
	before := a.Store.Get()
	w := runtimeRequest(a, "resume")
	if w.Code != 409 || !strings.Contains(w.Body.String(), "SERVICE_RUNTIME_UNCONFIGURED") || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("power enabled pending/all-LAN", w.Body.String())
	}
}

func TestServiceRuntimeReviewedNodeApplyWhileStoppedStartsOnlySelection(t *testing.T) {
	a, id, adapter, _ := serviceRuntimeFixture(t)
	if w := runtimeRequest(a, "stop"); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	before := a.Store.Get()
	// A failed replacement returns the complete stopped snapshot.
	adapter.after = func(p string) error {
		if p == "health" {
			return errors.New("fixture health failure")
		}
		return nil
	}
	review := reviewedNodeScope(t, a, id, &nodeScopeSelection{Mode: "selected", Sources: []string{"192.168.1.50/32"}})
	if w := nodeRouteRequest(a, id, "apply", nodeApplyBody(review), "owner-a", context.Background()); w.Code != 409 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("failed replacement lost suspension")
	}
	adapter.after = nil
	review = reviewedNodeScope(t, a, id, &nodeScopeSelection{Mode: "selected", Sources: []string{"192.168.1.50/32"}})
	if w := nodeRouteRequest(a, id, "apply", nodeApplyBody(review), "owner-a", context.Background()); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	after := a.Store.Get()
	if after.ServiceControl.Stopped || len(after.ServiceControl.SuspendedServices) != 0 || len(after.AppliedServices) != 1 || after.AppliedServices["telegram"].Sources[0] != "192.168.1.50/32" || !reflect.DeepEqual(after.Services["youtube"], before.Services["youtube"]) {
		t.Fatal("manual restart resumed other routes or lost pending")
	}
}

func TestServiceRuntimeStoppedRouteOnlyApplyRetainsSavedClientScope(t *testing.T) {
	a, _, _, _ := serviceRuntimeFixture(t)
	prior := a.Store.Get().AppliedServices["telegram"].Sources
	if w := runtimeRequest(a, "stop"); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	_ = a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "direct", Sources: []string{"192.168.1.42/32"}})
	// Keep other pending routes disabled for this selected route-only fixture.
	_ = a.Store.UpdateService("youtube", config.ServiceState{Enabled: false, Route: "direct"})
	before := a.Store.Get()
	planConfig := configForChangeScope(before, changeScopeServices)
	if !reflect.DeepEqual(planConfig.Services["telegram"].Sources, prior) {
		t.Fatal("service plan broadened stopped client scope")
	}
	review := genericReviewed(t, a, "?scope=services")
	w := genericApply(a, "?scope=services", review)
	if w.Code != 200 {
		t.Fatalf("route-only apply failed: %d %s", w.Code, w.Body.String())
	}
	after := a.Store.Get()
	if after.ServiceControl.Stopped || !reflect.DeepEqual(after.AppliedServices["telegram"].Sources, prior) || !reflect.DeepEqual(after.Services, before.Services) {
		t.Fatal("route-only apply broadened scope or consumed pending PC42")
	}
}
