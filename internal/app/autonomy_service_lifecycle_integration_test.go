package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
	"github.com/ArtixSx/razvilka/internal/security"
)

// Exercise the HTTP setup and service enrollment, scheduled HTTPS import, real
// plan compilation and transaction journal on a clean store. The service
// checker and adapter are modeled. Only the later health deadline is advanced.
func TestAutonomySavedServiceUsesScheduledFeedAppliesAndRepairs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	root := t.TempDir()
	a, err := newServiceLifecycleFixture(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Nodes.Close(); err != nil {
			t.Error(err)
		}
	})
	adapter := &nodeApplyAdapter{}
	if err := a.Dataplane.Register(adapter); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	firstRequest := make(chan struct{})
	releaseFeed := make(chan struct{})
	client := d10TLSFeedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/approved" || r.TLS == nil {
			http.Error(w, "unexpected source request", http.StatusNotFound)
			return
		}
		if requests.Add(1) == 1 {
			close(firstRequest)
		}
		select {
		case <-releaseFeed:
		case <-r.Context().Done():
			return
		}
		for i := range 3 {
			fmt.Fprintf(w, "vless://123e4567-e89b-12d3-a456-426614174000@candidate-%d.example:443?security=tls\n", i)
		}
	}))
	client.Timeout = 20 * time.Second
	feedDir := filepath.Join(root, "feeds")
	if err := os.Mkdir(feedDir, 0700); err != nil {
		t.Fatal(err)
	}
	a.NodeFeeds, err = providerfeed.OpenWithDependencies(a.Nodes, feedDir, client, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.NodeFeeds.Close(); err != nil {
			t.Error(err)
		}
	})
	source, err := a.NodeFeeds.Save(ctx, "", providerfeed.SaveRequest{
		Request: providerfeed.Request{URL: "https://feed.example.test/approved", Limit: 3}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := autonomy.Default()
	policy.SetupComplete, policy.Enabled = true, true
	policy.DefaultSources = []string{"192.168.1.42/32"}
	policy.SourceIDs, policy.PreferredRoutes = []string{source.SourceID}, nil
	policy.ReserveTarget = 2
	policy.Application.Mode, policy.Components.Mode = "off", "off"
	handler := a.Handler(http.NotFoundHandler())
	send := func(method, path string, body any, expected int) *httptest.ResponseRecorder {
		t.Helper()
		r := autonomyRequest(method, path, body).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+awgAPIToken)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != expected {
			t.Fatalf("%s %s: status %d, want %d: %s", method, path, w.Code, expected, w.Body.String())
		}
		return w
	}
	setup := send(http.MethodPut, "/api/v1/autonomy", map[string]any{
		"expected_revision": 0, "policy": policy, "confirm": "SAVE_AUTONOMY", "release_safe_mode": true,
	}, http.StatusOK)
	if len(a.CustomServices.List()) != 0 || !strings.Contains(setup.Body.String(), "Built-in video") || len(a.Store.Get().AppliedServices) != 0 {
		t.Fatal("empty personal catalog concealed a built-in service or created an active route")
	}
	const id = "custom-owned-https"
	wantScope := []string{"192.168.1.50/32"}
	send(http.MethodPost, "/api/v1/custom-services", catalog.Service{
		ID: id, Name: "Owned HTTPS", Category: "Lab", CIDRs: []string{"93.184.216.34/32"}, ProbeURL: "https://example.org/",
	}, http.StatusCreated)
	snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
	if err != nil || len(snapshot.Nodes) != 0 {
		t.Fatal("the clean test started with profiles", err)
	}

	var checked []string
	var firstProof time.Time
	var loseHealth, observedLoss atomic.Bool
	var committedCount atomic.Int32
	adapter.after = func(phase string) error {
		if phase == "health" && loseHealth.CompareAndSwap(true, false) {
			observedLoss.Store(true)
			return errors.New("owned local process lost")
		}
		if phase == "commit" {
			committedCount.Add(1)
		}
		return nil
	}
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		if req.Service.ID != id || len(req.Outbound) == 0 {
			return dataplane.NodeCheckResult{}, errors.New("unexpected service or missing exact outbound")
		}
		checked = append(checked, req.NodeID)
		result := d10Result(req, "sing-box", true)
		if firstProof.IsZero() {
			firstProof = result.FinishedAt
		}
		return result, nil
	})
	workerCtx, stopWorkers := context.WithCancel(ctx)
	a.StartServiceReconciler(workerCtx)
	joinWorkers := sync.OnceFunc(func() {
		stopWorkers()
		waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer waitCancel()
		if err := a.WaitNodeFeeds(waitCtx); err != nil {
			t.Error("feed worker did not join", err)
		}
		if err := a.WaitServiceReconciler(waitCtx); err != nil {
			t.Error("service reconciler did not join", err)
		}
	})
	defer joinWorkers()
	waitForLifecycleState(t, ctx, func() bool {
		a.reconciler.mu.Lock()
		defer a.reconciler.mu.Unlock()
		return slices.ContainsFunc(a.reconciler.doc.Operations, func(op automationOperation) bool {
			return op.Kind == "feeds" && op.ID != 0 && op.State == "completed"
		})
	}, "initial scheduled cycle with no active services")
	if _, committed, err := a.Dataplane.Committed(); err != nil || committed || len(a.Store.Get().AppliedServices) != 0 {
		t.Fatal("empty active service list reached the data plane", err)
	}
	a.StartNodeFeeds(workerCtx)
	started := time.Now()
	send(http.MethodPost, "/api/v1/autonomy/services", map[string]any{
		"service_id": id, "enabled": true, "sources": wantScope,
		"expected_revision": a.autonomyPolicy().Revision, "confirm": "MANAGE_SERVICE",
	}, http.StatusOK)
	firstApplyCtx, cancelFirstApply := context.WithDeadline(ctx, started.Add(20*time.Second))
	defer cancelFirstApply()
	select {
	case <-firstRequest:
	case <-firstApplyCtx.Done():
		t.Fatal("enrolling a service did not trigger the scheduled subscription")
	}
	waitForLifecycleState(t, firstApplyCtx, func() bool {
		r := lifecycleServiceRuntime(a, id)
		return r.State == "searching" && r.Search != nil && r.Search.Exhausted && len(r.Search.Ordered) == 0
	}, "cold search while the scheduled subscription is in flight")
	if a.Store.Get().AppliedServices[id].Enabled {
		t.Fatal("HTTP enrollment applied an unchecked route")
	}
	close(releaseFeed)
	waitForLifecycleState(t, firstApplyCtx, func() bool {
		return lifecycleServiceRuntime(a, id).State == "applied"
	}, "automatically committed exact candidate after source import")
	appliedAt := time.Now()
	cfg := a.Store.Get()
	firstRoute := selectedRoute(cfg.AppliedServices[id])
	if !cfg.AppliedServices[id].Enabled || !reflect.DeepEqual(cfg.AppliedServices[id].Sources, wantScope) {
		t.Fatal("the confirmed route did not commit the selected device scope", cfg.AppliedServices[id])
	}
	committed, found, err := a.Dataplane.Committed()
	if err != nil || !found || len(committed.Routes) != 1 || committed.Routes[0].ServiceID != id || cfg.AppliedServices["video"].Enabled {
		t.Fatal("application widened scope or activated an unselected service", err)
	}
	snapshot, err = a.Nodes.Snapshot(ctx, time.Now())
	if err != nil || len(snapshot.Nodes) != 3 || requests.Load() != 1 {
		t.Fatal("scheduled subscription did not import all three profiles", err, len(snapshot.Nodes), requests.Load())
	}

	// Move only the recurring check clock forward. The controller must verify
	// the same remote node and run a fresh transaction after local health loss.
	lostAt := time.Now()
	loseHealth.Store(true)
	runtime := lifecycleServiceRuntime(a, id)
	runtime.NextCheck = time.Time{}
	a.autonomyRuntime(a.autonomyPolicy().Revision, id, runtime)
	a.wakeAutonomy()
	waitForLifecycleState(t, ctx, func() bool {
		return observedLoss.Load() && committedCount.Load() == 2 && lifecycleServiceRuntime(a, id).State == "applied"
	}, "background local runtime recovery")
	repairedAt := time.Now()
	joinWorkers()
	state := lifecycleServiceRuntime(a, id)
	activations := 0
	for _, phase := range adapter.calls {
		if phase == "activate" {
			activations++
		}
	}
	if len(checked) != 2 || checked[0] != checked[1] || "sing-box:"+checked[0] != firstRoute ||
		selectedRoute(a.Store.Get().AppliedServices[id]) != firstRoute || !slices.Contains(adapter.calls, "canary") ||
		activations != 2 {
		t.Fatal("first Apply or original-route repair was not a complete transaction", state, checked, adapter.calls)
	}
	t.Logf("controlled dispatcher: first exact proof %s, committed route observed %s, first Apply checked 1 of %d", firstProof.Sub(started), appliedAt.Sub(started), len(snapshot.Nodes))
	t.Logf("controlled dispatcher: local process recovery observed after %s", repairedAt.Sub(lostAt))
}

func newServiceLifecycleFixture(root string) (*App, error) {
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		return nil, err
	}
	custom, err := customservices.Load(filepath.Join(root, "custom.json"))
	if err != nil {
		return nil, err
	}
	gate, err := security.NewGate(awgAPIToken)
	if err != nil {
		return nil, err
	}
	nodeDir := filepath.Join(root, "nodes")
	if err := os.Mkdir(nodeDir, 0700); err != nil {
		return nil, err
	}
	nodes, err := nodestore.Open(nodeDir)
	if err != nil {
		return nil, err
	}
	manager := dataplane.New(filepath.Join(root, "dataplane"))
	manager.FreshProfile = stableNodeProfile
	a := &App{Store: store, CustomServices: custom, Security: gate, Nodes: nodes, Dataplane: manager, FreshProfile: stableNodeProfile,
		Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "video", Name: "Built-in video", Domains: []string{"video.example"}}}}}
	a.DataplaneHost = func() dataplane.HostState { return dataplane.HostState{IPCommand: true, TUN: true, SingBox: true} }
	a.nodeReviews.options = func() []routecatalog.Option {
		options := []routecatalog.Option{{ID: "direct", Installed: true, Configured: true, Selectable: true}, {ID: "sing-box", Installed: true, Configured: true}}
		if snapshot, err := nodes.Snapshot(context.Background(), time.Now()); err == nil {
			for _, n := range snapshot.Nodes {
				options = append(options, routecatalog.Option{ID: "sing-box:" + n.ID, Installed: true, Configured: true, Selectable: true, Services: []string{"custom-owned-https"}})
			}
		}
		return options
	}
	return a, nil
}

func lifecycleServiceRuntime(a *App, id string) autonomy.Runtime {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	return a.autonomy.doc.Runtime[id].Clone()
}

func waitForLifecycleState(t *testing.T, ctx context.Context, ready func() bool, description string) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for !ready() {
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", description)
		case <-ticker.C:
		}
	}
}

func TestAutonomyWholeLANScopesOnlySelectedServices(t *testing.T) {
	a, _, adapter := autonomousIntegrationFixture(t)
	const first = "my-independent-site"
	const second = "telegram"
	ctx := context.Background()
	if err := a.Store.UpdateService(second, config.ServiceState{Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.UpdateService("youtube", config.ServiceState{}); err != nil {
		t.Fatal(err)
	}
	enroll := func(id string, allLAN bool, sources []string) {
		t.Helper()
		w := httptest.NewRecorder()
		a.autonomyEnroll(w, autonomyRequest(http.MethodPost, "/api/v1/autonomy/services", map[string]any{
			"service_id": id, "enabled": true, "all_lan": allLAN, "sources": sources,
			"expected_revision": a.autonomyPolicy().Revision, "confirm": "MANAGE_SERVICE",
		}))
		if w.Code != http.StatusOK {
			t.Fatalf("enrollment %s: %d %s", id, w.Code, w.Body.String())
		}
	}
	enroll(first, true, nil)
	var firstApplied config.ServiceState
	var checkedSecond bool
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		if req.Service.ID == second {
			checkedSecond = true
			if !reflect.DeepEqual(a.Store.Get().AppliedServices[first], firstApplied) {
				t.Fatal("the working service changed during exact proof of the second service")
			}
		}
		return d10Result(req, "sing-box", true), nil
	})
	a.autonomyRound(ctx, time.Now())
	firstApplied = a.Store.Get().AppliedServices[first]
	plan, exists, err := a.Dataplane.Committed()
	if err != nil || !exists || len(plan.Routes) != 1 || plan.Routes[0].ServiceID != first ||
		len(plan.Routes[0].Sources) != 0 || !slices.Equal(plan.Routes[0].CIDRs, []string{"93.184.216.34/32"}) ||
		!firstApplied.Enabled || len(firstApplied.Sources) != 0 {
		t.Fatal("whole-LAN source intent did not retain the exact selected destination", err, exists, plan.Routes)
	}
	wantScope := []string{"192.168.1.50/32"}
	enroll(second, false, wantScope)
	a.autonomyRound(ctx, time.Now())
	if after := a.Store.Get().AppliedServices; !reflect.DeepEqual(after[first], firstApplied) || after[second].Enabled {
		t.Fatal("activation changed the working path before checking the second service", after)
	}
	a.autonomyRound(ctx, time.Now())
	after, _, err := a.Dataplane.Committed()
	if err != nil || !checkedSecond || !reflect.DeepEqual(a.Store.Get().AppliedServices[first], firstApplied) || len(after.Routes) != 2 ||
		!slices.ContainsFunc(after.Routes, func(route dataplane.Route) bool {
			return route.ServiceID == second && slices.Equal(route.Sources, wantScope) && slices.Equal(route.CIDRs, []string{"149.154.160.0/20"})
		}) || a.Store.Get().AppliedServices["youtube"].Enabled || !slices.Contains(adapter.calls, "commit") {
		t.Fatal("adding the second service did not preserve the committed first service and exact new scope", err, checkedSecond, after.Routes)
	}
}

func TestAutonomyResumeBeforeFirstApplyRespectsSavedExclusion(t *testing.T) {
	ctx := context.Background()
	const id = "custom-owned-https"
	a, err := newServiceLifecycleFixture(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Nodes.Close() })
	adapter := &nodeApplyAdapter{}
	if err := a.Dataplane.Register(adapter); err != nil {
		t.Fatal(err)
	}
	a.Catalog.Services = append(a.Catalog.Services, catalog.Service{
		ID: id, Name: "Owned HTTPS", CIDRs: []string{"93.184.216.34/32"}, ProbeURL: "https://example.org/",
	})
	if _, err := a.Nodes.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"},
		"vless://123e4567-e89b-12d3-a456-426614174000@private.example:443?security=tls", time.Now(), time.Hour, false); err != nil {
		t.Fatal(err)
	}
	handler := a.Handler(http.NotFoundHandler())
	send := func(method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		req := autonomyRequest(method, path, body)
		req.Header.Set("Authorization", "Bearer "+awgAPIToken)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s failed: %d %s", method, path, w.Code, w.Body.String())
		}
		return w
	}
	p := autonomy.Default()
	p.SetupComplete, p.Enabled, p.InheritNewServices = true, true, true
	p.DefaultSources = []string{"192.168.1.50/32"}
	p.SourceIDs, p.PreferredRoutes = []string{"manual"}, nil
	p.Application.Mode, p.Components.Mode = "off", "off"
	send(http.MethodPut, "/api/v1/autonomy", map[string]any{
		"expected_revision": 0, "policy": p, "confirm": "SAVE_AUTONOMY", "release_safe_mode": true,
	})
	send(http.MethodPut, "/api/v1/services/"+id, config.ServiceState{Enabled: true, Route: "auto"})
	save := func(path string, body map[string]any) {
		t.Helper()
		body["expected_revision"] = a.Store.Get().Revision
		w := send(http.MethodPost, path, body)
		if !strings.Contains(w.Body.String(), `"live_applied":false`) {
			t.Fatalf("%s changed the network: %s", path, w.Body.String())
		}
	}
	save("/api/v1/service-control/runtime", map[string]any{"action": "stop", "confirm": "STOP_OWNED_ROUTES"})
	if !a.Store.Get().ServiceControl.Stopped {
		t.Fatal("missing stopped intent")
	}
	save(resourceExclusionsPath, map[string]any{
		"expected_policy_revision": 0, "expected_exclusion_revision": 0,
		"manual": []config.ResourceMatch{{Kind: "service", Value: id}},
	})
	save("/api/v1/service-control/runtime", map[string]any{"action": "resume", "confirm": "RESUME_OWNED_ROUTES"})
	checks := 0
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checks++
		return d10Result(req, "sing-box", true), nil
	})
	a.autonomyRound(ctx, time.Now())
	cfg := a.Store.Get()
	if cfg.ServiceControl.Stopped || !cfg.Services[id].Enabled || cfg.AppliedServices[id].Enabled ||
		lifecycleServiceRuntime(a, id).State != "excluded" || checks != 0 || len(adapter.calls) != 0 {
		t.Fatal("Resume skipped a fresh exclusion or lost service intent", lifecycleServiceRuntime(a, id), checks, adapter.calls)
	}
}
