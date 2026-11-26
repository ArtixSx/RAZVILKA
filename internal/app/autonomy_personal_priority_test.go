package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

func TestAutonomyPersonalPriorityUsesShortLocalStageThenAppliesMarkedProfile(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	marked := ids[1]
	all := sourcePriorityImport(t, a, ids[0], "priority", "external.example")
	sourcePriorityImport(t, a, marked, "priority", "") // The same material also has a public origin.
	d10Options(a, all)
	options := a.nodeReviews.options
	a.nodeReviews.options = func() []routecatalog.Option {
		return append(options(),
			routecatalog.Option{ID: "nfqws2", Installed: true, Configured: true, Running: true, Selectable: true, Ready: true},
			routecatalog.Option{ID: "warp-wg", Installed: true, Configured: true, Running: true, Selectable: true, Ready: true})
	}
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.PreferredRoutes = []string{"warp-wg", "nfqws2"}
	a.autonomy.mu.Unlock()
	sourcePriorityPolicy(t, a, 1)
	response := httptest.NewRecorder()
	a.nodeAction(response, autonomyRequest(http.MethodPatch, "/api/v1/nodes/"+marked, map[string]bool{"priority_check": true}))
	if response.Code != http.StatusOK {
		t.Fatalf("set priority: %d %s", response.Code, response.Body.String())
	}
	var trace []string
	a.TestLab = testlab.NewRunner()
	a.RouteProber = autonomyResourceRouteProber(func(ctx context.Context, service catalog.Service, route string) testlab.Result {
		trace = append(trace, route)
		deadline, _ := ctx.Deadline()
		if route == "nfqws2" && (deadline.IsZero() || time.Until(deadline) > 5*time.Second) {
			t.Error("short local phase did not receive its own deadline")
		}
		return testlab.Result{ServiceID: service.ID, Route: route, Status: "not-ready", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	})
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		trace = append(trace, req.NodeID)
		return d10Result(req, "sing-box", req.NodeID == marked), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	if runtime := autonomyTestState(a); runtime.State != "applied" || !slices.Equal(trace, []string{"nfqws2", marked}) || !slices.Contains(adapter.calls, "commit") {
		t.Fatalf("priority did not apply through the first-usable lane: %s, %v, %v", runtime.State, trace, adapter.calls)
	}
}

func TestAutonomyPersonalPriorityNeedsFreshPersonalConsentEvenForDualOrigin(t *testing.T) {
	now := time.Now().UTC()
	priority := nodestore.Node{ID: "marked", PriorityCheck: true, Protocol: "VLESS", Origins: []nodestore.Origin{
		{SourceID: "manual", ReceivedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)},
		{SourceID: "public", ReceivedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)},
	}}
	snapshot := nodestore.Snapshot{Sources: []nodestore.Source{{ID: "manual", Kind: "manual"}, {ID: "public", Kind: "community"}}, Nodes: []nodestore.Node{priority}}
	p := autonomy.Default()
	p.SourceIDs = []string{"public"}
	if !allowedAutonomyNode(p, priority, now) || autonomyPersonalPriorities(p, snapshot, now)[priority.ID] {
		t.Fatal("public consent activated private scheduling priority")
	}
	p.SourceIDs = append(p.SourceIDs, "manual")
	if !autonomyPersonalPriorities(p, snapshot, now)[priority.ID] || autonomyPersonalPriorities(p, snapshot, now.Add(2*time.Minute))[priority.ID] {
		t.Fatal("priority failed to respect personal provenance, consent or expiration")
	}
}

func TestAutonomyPersonalPriorityChangeOrdersReplacementAfterConfirmedFailure(t *testing.T) {
	a, ids, adapter := autonomyThreeReserveFixture(t)
	ctx := context.Background()
	current, marked := ids[0], ids[2]
	before := a.Store.Get()
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, autonomyRequest(http.MethodPatch, "/api/v1/nodes/"+marked, map[string]bool{"priority_check": true}))
	if w.Code != http.StatusOK || a.Store.Get().Revision != before.Revision || len(adapter.calls) != 0 {
		t.Fatalf("priority change modified the current route: HTTP %d, adapter=%v", w.Code, adapter.calls)
	}
	var checked []string
	currentWorks := true
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		return d10Result(req, "sing-box", req.NodeID != current || currentWorks), nil
	})
	autonomyTestDue(a, false)
	a.autonomyRound(ctx, time.Now())
	if autonomyTestState(a).State != "healthy" || !slices.Equal(checked, []string{current}) ||
		!slices.Equal(adapter.calls, []string{"health"}) || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+current {
		t.Fatalf("preference displaced a healthy route: checks=%v, adapter=%v", checked, adapter.calls)
	}
	checked, adapter.calls, currentWorks = nil, nil, false
	autonomyConfirmFailure(t, a, ctx)
	if autonomyTestState(a).State != "applied" || !slices.Equal(checked, []string{current, current, marked}) ||
		!slices.Contains(adapter.calls, "commit") || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+marked {
		t.Fatalf("updated priority did not lead the new replacement queue: checks=%v, adapter=%v", checked, adapter.calls)
	}
}

func TestNodePersonalPriorityAtImportCanBeChangedWithoutRouteOrConsentMutation(t *testing.T) {
	a, _, _ := autonomousIntegrationFixture(t)
	before := a.Store.Get()
	p := a.autonomyPolicy()
	uri := "vless://123e4567-e89b-12d3-a456-426614174002@fresh-priority.example:443?security=tls"
	w := httptest.NewRecorder()
	a.nodeImport(w, autonomyRequest(http.MethodPost, "/api/v1/nodes/import", map[string]any{
		"profile": uri, "confirm": "STORE_REMOTE_NODES", "priority_check": true,
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("import priority: %d %s", w.Code, w.Body.String())
	}
	view, err := a.Nodes.SnapshotWithPriority(context.Background(), time.Now())
	marked := ""
	for _, n := range view.Nodes {
		if n.PriorityCheck {
			marked = n.ID
		}
	}
	if err != nil || marked == "" || len(view.Nodes) != 3 {
		t.Fatal("accepted profile did not receive priority", err)
	}
	w = httptest.NewRecorder()
	a.nodeAction(w, autonomyRequest(http.MethodPatch, "/api/v1/nodes/"+marked, map[string]any{"priority_check": false, "disabled": true}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous mutation accepted: %d", w.Code)
	}
	w = httptest.NewRecorder()
	a.nodeAction(w, autonomyRequest(http.MethodPatch, "/api/v1/nodes/"+marked, map[string]bool{"priority_check": false}))
	if w.Code != http.StatusOK {
		t.Fatalf("clear priority: %d %s", w.Code, w.Body.String())
	}
	view, err = a.Nodes.SnapshotWithPriority(context.Background(), time.Now())
	if err != nil || slices.ContainsFunc(view.Nodes, func(n nodestore.Node) bool { return n.PriorityCheck }) || a.Store.Get().Revision != before.Revision || a.autonomyPolicy().Revision != p.Revision {
		t.Fatal("priority change altered a route, consent or node state", err)
	}
}
