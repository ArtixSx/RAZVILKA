package app

import (
	"context"
	"errors"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

// Real stores, plan compiler and transaction manager; only the network checker,
// host capabilities and OS adapter are replaced. This is NOT router evidence.
func autonomousIntegrationFixture(t *testing.T) (*App, []string, *nodeApplyAdapter) {
	t.Helper()
	a, _, adapter := nodeApplyFixture(t)
	a.Catalog.Services = append(a.Catalog.Services, catalog.Service{ID: "my-independent-site", Name: "My service", Domains: []string{"example.org"}, ProbeURL: "https://example.org/"})
	snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174001@reserve.example:443?security=tls", time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, n := range snapshot.Nodes {
		ids = append(ids, n.ID)
	}
	slices.Sort(ids)
	a.nodeReviews.options = func() []routecatalog.Option {
		out := []routecatalog.Option{{ID: "direct", Installed: true, Configured: true, Selectable: true}, {ID: "sing-box", Installed: true, Configured: true, Selectable: true}}
		for _, id := range ids {
			out = append(out, routecatalog.Option{ID: "sing-box:" + id, Installed: true, Configured: true, Selectable: true, Services: []string{"my-independent-site", "telegram"}})
		}
		return out
	}
	p := autonomy.Default()
	p.SetupComplete = true
	p.Enabled = true
	p.InheritNewServices = true
	p.DefaultSources = []string{"192.168.1.50/32"}
	p.SourceIDs = []string{"manual"}
	p.PreferredRoutes = nil
	p.ReserveTarget = 2
	p.Application.Mode = "off"
	p.Components.Mode = "off"
	w := httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": 0, "policy": p, "confirm": "SAVE_AUTONOMY", "release_safe_mode": true}))
	if w.Code != 200 {
		t.Fatalf("setup %d %s", w.Code, w.Body.String())
	}
	if err = a.inheritAutonomyService(context.Background(), "my-independent-site"); err != nil {
		t.Fatal(err)
	}
	return a, ids, adapter
}
func autonomyTestDue(a *App, confirmFailure bool) {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	r := a.autonomy.doc.Runtime["my-independent-site"]
	r.NextCheck = time.Time{}
	if confirmFailure {
		r.FirstFailure = time.Now().Add(-time.Minute)
		r.LastFailure = time.Now().Add(-time.Minute)
	}
	a.autonomy.doc.Runtime["my-independent-site"] = r
	_ = a.persistAutonomyLocked(context.Background())
}
func autonomyTestState(a *App) autonomy.Runtime {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	return a.autonomy.doc.Runtime["my-independent-site"].Clone()
}
func TestAutonomyEndToEndAssignmentStickyFailoverAndRollback(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	before := a.Store.Get()
	fail := map[string]bool{}
	a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		result := autofallbackResult(r, !fail[r.NodeID])
		if fail[r.NodeID] {
			result.Stage = "egress"
			result.TestLevel = "protocol"
			result.ErrorCode = "node-egress-failed"
		}
		return result, nil
	})
	a.autonomyRound(context.Background(), time.Now())
	r := autonomyTestState(a)
	if r.State != "applied" {
		t.Fatalf("initial assignment: %+v calls=%v", r, adapter.calls)
	}
	cfg := a.Store.Get()
	first := selectedRoute(cfg.AppliedServices["my-independent-site"])
	if first != "sing-box:"+ids[0] || !reflect.DeepEqual(cfg.Services["youtube"], before.Services["youtube"]) || !reflect.DeepEqual(cfg.AppliedServices["my-independent-site"].Sources, []string{"192.168.1.50/32"}) {
		t.Fatal("wrong scope, node or collateral write", first)
	}
	adapter.calls = nil
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Now())
	if r = autonomyTestState(a); r.State != "healthy" || len(adapter.calls) != 0 {
		t.Fatal("healthy path not sticky", r, adapter.calls)
	}
	fail[ids[0]] = true
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Now())
	if r = autonomyTestState(a); r.Failures != 1 || len(adapter.calls) != 0 {
		t.Fatalf("first failure: %+v calls=%v", r, adapter.calls)
	}
	autonomyTestDue(a, true)
	a.autonomyRound(context.Background(), time.Now())
	if r = autonomyTestState(a); r.State != "applied" || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+ids[1] {
		t.Fatalf("no failover: %+v calls=%v", r, adapter.calls)
	}
	if !slices.Contains(adapter.calls, "canary") || !slices.Contains(adapter.calls, "commit") {
		t.Fatal("transaction bypassed")
	}
	// Next candidate fails activation health: previous committed state must remain.
	fail[ids[0]] = false
	fail[ids[1]] = true
	adapter.calls = nil
	adapter.after = func(phase string) error {
		if phase == "health" {
			return errors.New("injected health failure")
		}
		return nil
	}
	rollbackBase := a.Store.Get()
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Now())
	autonomyTestDue(a, true)
	a.autonomyRound(context.Background(), time.Now())
	if r = autonomyTestState(a); r.State != "apply-refused" || !reflect.DeepEqual(rollbackBase, a.Store.Get()) || !slices.Contains(adapter.calls, "rollback") {
		t.Fatalf("rollback missing: %+v %v", r, adapter.calls)
	}
}
func TestAutonomyInconclusiveDoesNotSwitchOrIncreaseFailureQuorum(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return autofallbackResult(r, true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	before := a.Store.Get()
	adapter.calls = nil
	a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		x := autofallbackResult(r, false)
		x.Verdict = evidence.VerdictInconclusive
		return x, nil
	})
	for range 3 {
		autonomyTestDue(a, true)
		a.autonomyRound(context.Background(), time.Now())
	}
	if r := autonomyTestState(a); r.Failures != 0 || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatalf("ambiguity changed route: %+v ids=%v", r, ids)
	}
}
func TestAutonomyPendingRemovalDisablesOwnDraftWithoutApplyingOtherDrafts(t *testing.T) {
	a, _, _ := autonomousIntegrationFixture(t)
	// Explicitly queued service with a not-yet-applied draft must be removable.
	if err := a.Store.UpdateService("my-independent-site", config.ServiceState{Enabled: true, Route: "auto", Sources: []string{"192.168.1.50/32"}}); err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	if _, err := a.requestAutonomyRemoval(context.Background(), "my-independent-site", false); err != nil {
		t.Fatal(err)
	}
	a.autonomyRound(context.Background(), time.Now())
	after := a.Store.Get()
	if after.Services["my-independent-site"].Enabled || !reflect.DeepEqual(before.Services["youtube"], after.Services["youtube"]) {
		t.Fatal("pending removal did not disable own draft or changed another")
	}
}
