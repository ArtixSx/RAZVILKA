package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/testlab"
	"github.com/ArtixSx/razvilka/internal/warp"
)

func controlRequest(a *App, method, path string, body any) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(string(data))))
	return w
}

func serviceControlFixture(t *testing.T, count int) (*App, []string) {
	a, ids := newNodeJobTest(t, count)
	s, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	a.Store = s
	return a, ids
}

func startControlFixture(t *testing.T, a *App, kind string, ids []string) *httptest.ResponseRecorder {
	t.Helper()
	w := controlRequest(a, "POST", "/api/v1/service-control/jobs", map[string]any{"kind": kind, "service_ids": []string{"telegram"}, "node_ids": ids, "expected_revision": a.Store.Get().Revision})
	if w.Code != 202 {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	return w
}

func TestServiceControlSelectChecksBoundedCandidatesAndOnlyRecommends(t *testing.T) {
	a, ids := serviceControlFixture(t, 5)
	slices.Sort(ids)
	before := a.Store.Get()
	var calls atomic.Int32
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return autofallbackResult(request, calls.Add(1) == 2), nil
	})
	startControlFixture(t, a, "select", nil)
	job := joinNodeJob(t, a)
	if calls.Load() != 2 || job.State != "completed" || len(job.ServiceResults) != 1 {
		t.Fatalf("selection not bounded/completed: %+v", job)
	}
	result := job.ServiceResults[0]
	if !result.Available || result.RecommendedNodeID != ids[1] || result.Kind != "select" || result.AppliedRoute != "" || result.CheckedRoute != "sing-box:"+ids[1] || result.Scope.Mode != "unknown" || !result.ScopeRequired {
		t.Fatalf("recommendation broadened scope or claimed applied: %+v", result)
	}
	if !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("recommendation applied or rewrote pending")
	}
	view := a.serviceControlView()
	current := view["results"].([]serviceControlResult)[0]
	if current.Stale || !current.FreshnessVerified {
		t.Fatal("fresh completion was not validated")
	}
	original := a.Catalog.Services[0].ProbeURL
	a.Catalog.Services[0].ProbeURL = "https://telegram.org/different"
	if !a.serviceControlView()["results"].([]serviceControlResult)[0].Stale {
		t.Fatal("changed service probe retained a fresh PASS")
	}
	a.Catalog.Services[0].ProbeURL = original
	_ = a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "auto", Sources: []string{"192.168.1.40/32"}})
	if !a.serviceControlView()["results"].([]serviceControlResult)[0].Stale {
		t.Fatal("changed config retained fresh badge")
	}
}

func TestServiceControlRepeatedSelectionAdvancesAndPrefersFreshServiceSuccess(t *testing.T) {
	a, _ := serviceControlFixture(t, 7)
	var attempts []string
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		attempts = append(attempts, request.NodeID)
		return autofallbackResult(request, false), nil
	})
	startControlFixture(t, a, "select", nil)
	joinNodeJob(t, a)
	startControlFixture(t, a, "select", nil)
	joinNodeJob(t, a)
	if len(attempts) != 6 {
		t.Fatalf("selection exceeded per-round bound: %v", attempts)
	}
	for _, id := range attempts[3:] {
		if slices.Contains(attempts[:3], id) {
			t.Fatal("repeat checked the same dead shortlist")
		}
	}
	// A successful node for this exact service/network outranks unchecked nodes.
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return autofallbackResult(request, true), nil
	})
	startControlFixture(t, a, "select", nil)
	successful := joinNodeJob(t, a).ServiceResults[0].RecommendedNodeID
	var first string
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		first = request.NodeID
		return autofallbackResult(request, true), nil
	})
	startControlFixture(t, a, "select", nil)
	joinNodeJob(t, a)
	if successful == "" || first != successful {
		t.Fatal("fresh service success was not preferred")
	}
}

func TestServiceControlManualModeBlocksFallbackAndWARPAutomationWithoutErasingPolicy(t *testing.T) {
	a, _, _, adapter, _ := nodeAutofallbackFixture(t, 1)
	mode := "manual"
	if err := a.Store.UpdateServiceControl(&mode, nil, a.Store.Get().Revision); err != nil {
		t.Fatal(err)
	}
	called := false
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		called = true
		return autofallbackResult(request, false), nil
	})
	before := a.Store.Get()
	a.nodeAutofallbackRound(context.Background(), time.Now())
	if called || len(adapter.calls) > 0 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("global manual allowed fallback or changed permissions")
	}
	a.Warp = warp.New(filepath.Join(t.TempDir(), "warp"), t.TempDir(), a.EngineConfigs)
	policy := a.Warp.Health().Policy
	policy.Enabled, policy.AcceptTOS, policy.AutoGenerateCandidate, policy.AutoApplyCandidate = true, true, true, true
	if _, err := a.Warp.UpdateHealthPolicy(policy); err != nil {
		t.Fatal(err)
	}
	beforeWarp := a.Warp.Health()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	decision, err := a.processWarpHealth(ctx, []warp.HealthEvidence{{ServiceID: "telegram", Status: "fail", RouteConfirmed: true}})
	if err != nil || decision.ShouldGenerate || decision.Reason != "global-manual-or-stopped" || !reflect.DeepEqual(beforeWarp, a.Warp.Health()) {
		t.Fatal("manual mode rotated/rewrote WARP health policy", err)
	}
}

func TestServiceControlChecksAllSixtyFourServicesInSingleBoundedJob(t *testing.T) {
	a, _ := serviceControlFixture(t, 1)
	ids := []string{}
	a.Catalog.Services = nil
	for i := 0; i < 64; i++ {
		id := fmt.Sprintf("site-%d", i)
		ids = append(ids, id)
		a.Catalog.Services = append(a.Catalog.Services, catalog.Service{ID: id, Name: id, ProbeURL: "https://example.org/"})
	}
	a.TestLab = testlab.NewRunner()
	a.TestLab.Profile = func() string { p, _ := stableNodeProfile(context.Background()); return p }
	var calls atomic.Int32
	a.RouteProber = serviceRouteProbe(func(ctx context.Context, service catalog.Service, route string) testlab.Result {
		calls.Add(1)
		return testlab.Result{ServiceID: service.ID, Route: route, Status: "pass", RouteConfirmed: true, HTTPStatus: 200, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	})
	w := controlRequest(a, "POST", "/api/v1/service-control/jobs", map[string]any{"kind": "check", "service_ids": ids, "expected_revision": a.Store.Get().Revision})
	if w.Code != 202 {
		t.Fatal(w.Body.String())
	}
	job := joinNodeJob(t, a)
	if calls.Load() != 64 || job.Completed != 64 || job.Total != 64 || job.State != "completed" {
		t.Fatal("all-service batch truncated", calls.Load(), job.Completed)
	}
}

func TestServiceControlStoppedNonNodeCheckUsesSavedRouteWithoutApplying(t *testing.T) {
	a, _ := serviceControlFixture(t, 1)
	_ = a.Store.SetSafeMode(false)
	_ = a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "warp-wg", Sources: []string{"192.168.1.40/32"}})
	_ = a.Store.ApplyDraft()
	if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"telegram": "warp-wg"}, a.Store.Get().Revision); err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	a.TestLab = testlab.NewRunner()
	a.TestLab.Profile = func() string { p, _ := stableNodeProfile(context.Background()); return p }
	var selected string
	a.RouteProber = serviceRouteProbe(func(ctx context.Context, service catalog.Service, route string) testlab.Result {
		selected = route
		return testlab.Result{ServiceID: service.ID, Route: route, Status: "not-ready", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	})
	startControlFixture(t, a, "check", nil)
	job := joinNodeJob(t, a)
	if selected != "warp-wg" || len(job.ServiceResults) != 1 || job.ServiceResults[0].AppliedRoute != "" || job.ServiceResults[0].CheckedRoute != "warp-wg" || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("saved route was replaced by direct or automatically resumed")
	}
}

func TestServiceControlConcurrentStartsAndStaleCancelDoNotCancelNewJob(t *testing.T) {
	a, ids := serviceControlFixture(t, 1)
	entered, canceled, cleanup := make(chan struct{}), make(chan struct{}), make(chan struct{})
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-cleanup
		return dataplane.NodeCheckResult{}, ctx.Err()
	})
	startControlFixture(t, a, "select", ids)
	awaitOperation(t, entered)
	job := a.nodeCheckSnapshot()["job"].(*nodeCheckJob)
	second := controlRequest(a, "POST", "/api/v1/service-control/jobs", map[string]any{"kind": "select", "service_ids": []string{"telegram"}, "expected_revision": a.Store.Get().Revision})
	if second.Code != 409 {
		t.Fatal("concurrent job admitted", second.Code)
	}
	stale := controlRequest(a, "DELETE", fmt.Sprintf("/api/v1/service-control/current?job_id=%d", job.ID+1), nil)
	if stale.Code != 409 {
		t.Fatal("stale cancellation accepted")
	}
	select {
	case <-canceled:
		t.Fatal("competing start/stale ID canceled owner")
	default:
	}
	correct := controlRequest(a, "DELETE", fmt.Sprintf("/api/v1/service-control/current?job_id=%d", job.ID), nil)
	if correct.Code != 200 {
		t.Fatal("cancel unavailable")
	}
	awaitOperation(t, canceled)
	if release, err := a.Operations.Enter(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("cancel released admission before cleanup")
	}
	if w := controlRequest(a, "GET", "/api/v1/service-control/current", nil); w.Code != 200 {
		t.Fatal("active job status locked")
	}
	close(cleanup)
	final := joinNodeJob(t, a)
	if final.State != "canceled" || len(final.ServiceResults) != 1 || final.ServiceResults[0].Available {
		t.Fatal("canceled probe promoted result")
	}
}

type serviceRouteProbe func(context.Context, catalog.Service, string) testlab.Result

func (f serviceRouteProbe) Probe(ctx context.Context, s catalog.Service, route string) testlab.Result {
	return f(ctx, s, route)
}

func TestServiceControlPersistedTimerRunsWithoutBrowserInManualMode(t *testing.T) {
	a, _ := serviceControlFixture(t, 1)
	mode := "manual"
	schedule := config.ServiceCheckSchedule{Enabled: true, IntervalSeconds: 300, ServiceIDs: []string{"telegram"}}
	if err := a.Store.UpdateServiceControl(&mode, &schedule, a.Store.Get().Revision); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	a.TestLab = testlab.NewRunner()
	a.TestLab.Profile = func() string { p, _ := stableNodeProfile(context.Background()); return p }
	a.RouteProber = serviceRouteProbe(func(ctx context.Context, service catalog.Service, route string) testlab.Result {
		calls.Add(1)
		return testlab.Result{ServiceID: service.ID, ServiceName: service.Name, Route: route, Status: "pass", RouteConfirmed: true, HTTPStatus: 200, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	})
	now := time.Now()
	initReconcilerFixture(t, a, now)
	a.reconcileRound(context.Background(), now)
	if calls.Load() != 1 {
		t.Fatal("router timer did not check in manual mode", calls.Load())
	}
	data, err := os.ReadFile(a.Store.AutomationStatePath())
	if err != nil {
		t.Fatal(err)
	}
	var doc reconcilerDocument
	_ = json.Unmarshal(data, &doc)
	found := false
	for _, op := range doc.Operations {
		if op.Kind == "service-checks" && op.State == "completed" && !op.NextRun.Before(now.Add(300*time.Second)) {
			found = true
		}
	}
	if !found {
		t.Fatal("timer deadline not persisted")
	}
	b := &App{Store: a.Store, TestLab: a.TestLab, RouteProber: a.RouteProber, FreshProfile: stableNodeProfile, Catalog: a.Catalog}
	b.StartNodeChecks(context.Background())
	t.Cleanup(func() { _ = b.WaitNodeChecks(context.Background()) })
	b.reconciler.started, b.reconciler.path = true, a.Store.AutomationStatePath()
	if err := b.loadReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.reconcileRound(context.Background(), now.Add(time.Minute))
	if calls.Load() != 1 {
		t.Fatal("restart ignored persisted timer deadline")
	}
	b.reconcileRound(context.Background(), now.Add(301*time.Second))
	if calls.Load() != 2 {
		t.Fatal("persisted schedule was not resumed")
	}
}

func TestServiceControlTimerReceivesBudgetAfterEarlierReconcilerWork(t *testing.T) {
	for _, parentBudget := range []time.Duration{0, 10 * time.Second} {
		t.Run(parentBudget.String(), func(t *testing.T) {
			a, _ := serviceControlFixture(t, 1)
			mode := "manual"
			schedule := config.ServiceCheckSchedule{Enabled: true, IntervalSeconds: 300, ServiceIDs: []string{"telegram"}}
			if err := a.Store.UpdateServiceControl(&mode, &schedule, a.Store.Get().Revision); err != nil {
				t.Fatal(err)
			}
			// Model an earlier serial job taking longer than this timer's budget.
			// No sleeping is necessary: the round timestamp is intentionally old.
			roundStarted := time.Now().Add(-10 * time.Minute)
			initReconcilerFixture(t, a, roundStarted)
			ctx := context.Background()
			if parentBudget != 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, parentBudget)
				defer cancel()
			}
			calls := 0
			var probeDeadline time.Time
			var probeErr error
			a.TestLab = testlab.NewRunner()
			a.TestLab.Profile = func() string { p, _ := stableNodeProfile(context.Background()); return p }
			a.RouteProber = serviceRouteProbe(func(probeCtx context.Context, service catalog.Service, route string) testlab.Result {
				calls++
				probeDeadline, _ = probeCtx.Deadline()
				probeErr = probeCtx.Err()
				return testlab.Result{ServiceID: service.ID, ServiceName: service.Name, Route: route, Status: "pass", RouteConfirmed: true, HTTPStatus: 200, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
			})
			dispatchStarted := time.Now()
			a.reconcileRound(ctx, roundStarted)
			if calls != 1 || probeErr != nil || !probeDeadline.After(dispatchStarted) {
				t.Fatalf("earlier work starved timer: calls=%d error=%v deadline=%v", calls, probeErr, probeDeadline)
			}
			if parentDeadline, ok := ctx.Deadline(); ok && probeDeadline.After(parentDeadline) {
				t.Fatal("fresh task budget escaped parent deadline")
			}
			data, err := os.ReadFile(a.Store.AutomationStatePath())
			if err != nil {
				t.Fatal(err)
			}
			var doc reconcilerDocument
			if err = json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			for _, op := range doc.Operations {
				if op.Kind != "service-checks" {
					continue
				}
				if op.State != "completed" || op.Deadline.Before(dispatchStarted.Add(2*time.Minute)) || op.Deadline.After(time.Now().Add(2*time.Minute)) || op.NextRun.Before(dispatchStarted.Add(300*time.Second)) {
					t.Fatalf("timer budget/cadence not durably bounded at dispatch: %+v", op)
				}
				return
			}
			t.Fatal("missing timer journal entry")
		})
	}
}
