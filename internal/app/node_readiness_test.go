package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
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

// readinessChecker models only the general connectivity check. A service
// proof request fails the test: the pool must never ask for one.
type readinessChecker struct {
	mu      sync.Mutex
	calls   []string
	outcome func(id string) string
}

func (c *readinessChecker) Check(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
	panic("readiness pool requested a service proof")
}
func (c *readinessChecker) Recover(context.Context) error { return nil }
func (c *readinessChecker) CheckConnectivity(_ context.Context, r dataplane.NodeConnectivityRequest) (dataplane.NodeConnectivityResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, r.NodeID)
	result := readyConnectivity(r)
	result.ProbeID = fmt.Sprintf("readiness-%03d", len(c.calls))
	outcome := "pass"
	if c.outcome != nil {
		outcome = c.outcome(r.NodeID)
	}
	switch outcome {
	case "egress":
		result.Ready, result.Verdict, result.Stage, result.ErrorCode, result.HTTPStatus = false, evidence.VerdictError, "egress", "node-egress-failed", 0
	case "transport":
		result.Ready, result.Verdict, result.Stage, result.ErrorCode, result.HTTPStatus, result.DirectControl = false, evidence.VerdictError, "transport", "node-transport-failed", 0, "not_run"
	case "wan":
		result.Ready, result.Verdict, result.Stage, result.ErrorCode, result.HTTPStatus, result.DirectControl = false, evidence.VerdictInconclusive, "egress", "node-egress-control-unavailable", 0, "unavailable"
	}
	return result, nil
}
func (c *readinessChecker) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}
func (c *readinessChecker) last() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.calls) == 0 {
		return ""
	}
	return c.calls[len(c.calls)-1]
}

// readinessFixture: real stores and autopilot consent for one CIDR-only
// service, four permitted synthetic nodes with a 24-hour origin and no
// earlier check. Only the checker and the OS adapter are replaced.
func readinessFixture(t *testing.T) (*App, []string, map[string]string, *readinessChecker, *nodeApplyAdapter, time.Time) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nodes"), 0o700); err != nil {
		t.Fatal(err)
	}
	nodes, err := nodestore.Open(filepath.Join(root, "nodes"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nodes.Close() })
	start := time.Now().UTC()
	uris := map[string]string{}
	for i := 0; i < 4; i++ {
		raw := fmt.Sprintf("vless://123e4567-e89b-12d3-a456-42661417400%d@pool%d.example:443?security=tls", i, i)
		at := start.Add(time.Duration(i-5) * time.Second)
		snapshot, err := nodes.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, raw, at, 24*time.Hour, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range snapshot.Nodes {
			if len(n.Origins) == 1 && n.Origins[0].ReceivedAt.Equal(at) {
				uris[n.ID] = raw
			}
		}
	}
	ids := []string{}
	for id := range uris {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if len(ids) != 4 {
		t.Fatal("fixture nodes", len(ids))
	}
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	a := &App{Nodes: nodes, Store: store, FreshProfile: stableNodeProfile, Dataplane: dataplane.New(filepath.Join(root, "dataplane")),
		Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "my-independent-site", Name: "My service", CIDRs: []string{"93.184.216.34/32"}, ProbeURL: "https://example.org/"}}}}
	a.Dataplane.FreshProfile = stableNodeProfile
	a.DataplaneHost = func() dataplane.HostState { return dataplane.HostState{IPCommand: true, TUN: true, SingBox: true} }
	a.nodeReviews.options = func() []routecatalog.Option {
		out := []routecatalog.Option{{ID: "direct", Installed: true, Configured: true, Selectable: true}, {ID: "sing-box", Installed: true, Configured: true, Selectable: true}}
		for _, id := range ids {
			out = append(out, routecatalog.Option{ID: "sing-box:" + id, Installed: true, Configured: true, Selectable: true, Services: []string{"my-independent-site"}})
		}
		return out
	}
	adapter := &nodeApplyAdapter{}
	if err = a.Dataplane.Register(adapter); err != nil {
		t.Fatal(err)
	}
	p := autonomy.Default()
	p.SetupComplete, p.Enabled, p.InheritNewServices = true, true, true
	p.DefaultSources = []string{"192.168.1.50/32"}
	p.SourceIDs = []string{"manual"}
	p.PreferredRoutes = nil
	p.Application.Mode, p.Components.Mode = "off", "off"
	w := httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": 0, "policy": p, "confirm": "SAVE_AUTONOMY", "release_safe_mode": true}))
	if w.Code != 200 {
		t.Fatalf("setup %d %s", w.Code, w.Body.String())
	}
	if err = a.Store.UpdateService("my-independent-site", config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	if err = a.inheritAutonomyService(ctx, "my-independent-site"); err != nil {
		t.Fatal(err)
	}
	checker := &readinessChecker{}
	a.NodeChecker = checker
	return a, ids, uris, checker, adapter, start
}

func readinessEntry(a *App, id string) nodeReadinessEntry {
	a.nodeReadiness.mu.Lock()
	defer a.nodeReadiness.mu.Unlock()
	return a.nodeReadiness.entries[id]
}

func readinessAutonomyImage(t *testing.T, a *App) []byte {
	t.Helper()
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	data, err := json.Marshal(a.autonomy.doc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestNodeReadinessRotationAdvancesWrapsAndStaysSideEffectFree(t *testing.T) {
	a, ids, _, checker, adapter, start := readinessFixture(t)
	ctx := context.Background()
	cfg := a.Store.Get()
	nodesBefore, err := a.Nodes.Snapshot(ctx, start)
	if err != nil {
		t.Fatal(err)
	}
	autonomyBefore := readinessAutonomyImage(t, a)
	at := start.Add(time.Minute)
	tick := func(offset time.Duration, want string) {
		t.Helper()
		before := checker.count()
		a.nodeReadinessRound(ctx, at.Add(offset))
		got := ""
		if checker.count() > before {
			got = checker.last()
		}
		if checker.count()-before > 1 || got != want {
			t.Fatalf("tick %s checked %d node(s), last %q; want %q", offset, checker.count()-before, got, want)
		}
	}
	tick(0, ids[0])
	tick(10*time.Second, "") // spacing between rotation checks
	tick(31*time.Second, ids[1])
	tick(62*time.Second, ids[2])
	// Three fresh PASS nodes for the only engine: no further exploration.
	tick(93*time.Second, "")
	tick(124*time.Second, "")
	view := a.autonomyView(at.Add(124 * time.Second))["node_readiness"].(nodeReadinessView)
	if view.State != "warm" || view.Ready != 3 || view.Unchecked != 1 || view.BackingOff != 0 || view.Total != 4 || !strings.Contains(view.Message, "Готовы: 3") {
		t.Fatalf("status %+v", view)
	}
	// After the re-check interval the rotation wraps to the first node.
	tick(13*time.Minute, ids[0])
	if e := readinessEntry(a, ids[0]); !e.Ready || !e.PassAt.Equal(at.Add(13*time.Minute)) {
		t.Fatalf("refresh not recorded %+v", e)
	}
	// One warm node fails: the pool explores again and reaches the unchecked
	// node before re-checking the failed one.
	checker.outcome = func(id string) string {
		if id == ids[1] {
			return "egress"
		}
		return "pass"
	}
	tick(13*time.Minute+31*time.Second, ids[1])
	if e := readinessEntry(a, ids[1]); e.Failures != 1 || e.failing(at.Add(14*time.Minute)) || e.Ready {
		t.Fatalf("one failure must leave the node uncertain %+v", e)
	}
	tick(14*time.Minute+2*time.Second, ids[2])
	tick(14*time.Minute+33*time.Second, ids[3])
	// Ordering only: no service proof, settings, node store, autopilot
	// document or dataplane change.
	nodesAfter, err := a.Nodes.Snapshot(ctx, start)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg, a.Store.Get()) || !reflect.DeepEqual(nodesBefore, nodesAfter) || string(autonomyBefore) != string(readinessAutonomyImage(t, a)) || len(adapter.calls) != 0 {
		t.Fatal("readiness rotation had a side effect", adapter.calls)
	}
}

func TestNodeReadinessHourlyCap(t *testing.T) {
	a, ids, _, checker, _, start := readinessFixture(t)
	at := start.Add(time.Minute)
	stamps := make([]time.Time, nodeReadinessHourlyChecks)
	for i := range stamps {
		stamps[i] = at.Add(-59 * time.Minute)
	}
	a.nodeReadiness.checks = stamps
	a.nodeReadinessRound(context.Background(), at)
	if checker.count() != 0 || a.nodeReadinessSnapshot(at).State != "limited" {
		t.Fatal("hourly cap ignored", checker.calls, a.nodeReadinessSnapshot(at))
	}
	a.nodeReadinessRound(context.Background(), at.Add(61*time.Second))
	if checker.count() != 1 || checker.last() != ids[0] || len(a.nodeReadiness.checks) != 1 {
		t.Fatal("cap did not roll over", checker.calls, len(a.nodeReadiness.checks))
	}
}

func TestNodeReadinessBackoffGrowsAndFeedRefreshResets(t *testing.T) {
	a, ids, uris, checker, _, start := readinessFixture(t)
	ctx := context.Background()
	for _, id := range ids[1:] {
		if _, err := a.Nodes.SetDisabled(ctx, id, true, start); err != nil {
			t.Fatal(err)
		}
	}
	checker.outcome = func(string) string { return "egress" }
	node := ids[0]
	delay := func() time.Duration { e := readinessEntry(a, node); return e.Next.Sub(e.CheckedAt) }
	within := func(d, base time.Duration) bool { return d >= base && d <= base+nodeReadinessJitter }
	at := start.Add(time.Minute)
	a.nodeReadinessRound(ctx, at)
	if e := readinessEntry(a, node); checker.count() != 1 || e.Failures != 1 || e.failing(at) || !within(delay(), nodeReadinessRecheck) {
		t.Fatalf("first failure %+v", e)
	}
	if a.nodeReadinessRound(ctx, at.Add(9*time.Minute)); checker.count() != 1 {
		t.Fatal("node re-checked before ten minutes")
	}
	at = readinessEntry(a, node).Next
	a.nodeReadinessRound(ctx, at)
	if e := readinessEntry(a, node); checker.count() != 2 || e.Failures != 2 || !e.failing(at) || !within(delay(), nodeReadinessBackoff) {
		t.Fatalf("second failure %+v", e)
	}
	at = readinessEntry(a, node).Next
	a.nodeReadinessRound(ctx, at)
	if e := readinessEntry(a, node); checker.count() != 3 || e.Failures != 3 || !within(delay(), 2*nodeReadinessBackoff) {
		t.Fatalf("third failure %+v", e)
	}
	if view := a.nodeReadinessSnapshot(at); view.BackingOff != 1 || view.Ready != 0 {
		t.Fatalf("status %+v", view)
	}
	at = at.Add(15 * time.Minute)
	if a.nodeReadinessRound(ctx, at); checker.count() != 3 {
		t.Fatal("node checked during its backoff")
	}
	// The feed delivers the node again: its schedule starts over. The origin
	// time stays real; the checker's own guard reads the store at real time.
	if _, err := a.Nodes.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, uris[node], start, 24*time.Hour, false); err != nil {
		t.Fatal(err)
	}
	at = at.Add(time.Second)
	a.nodeReadinessRound(ctx, at)
	if e := readinessEntry(a, node); checker.count() != 4 || e.Failures != 1 || e.failing(at) {
		t.Fatalf("feed refresh did not reset the backoff %+v", e)
	}
}

func TestNodeReadinessScheduleNeedsControlAndTwoFailures(t *testing.T) {
	at := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	pass := nodeCheckItem{Engine: "sing-box", TestLevel: "connectivity", Stage: "connectivity", Verdict: "PASS", DirectControl: "measured", CleanupVerified: true, ConnectivityReady: true}
	egress := nodeCheckItem{Engine: "sing-box", TestLevel: "connectivity", Stage: "egress", Verdict: "ERROR", ErrorCode: "node-egress-failed", DirectControl: "measured", CleanupVerified: true}
	transport := nodeCheckItem{Engine: "sing-box", TestLevel: "connectivity", Stage: "transport", Verdict: "ERROR", ErrorCode: "node-transport-failed", DirectControl: "not_run", CleanupVerified: true}
	r := &nodeReadinessState{entries: map[string]nodeReadinessEntry{"dead": {}, "good": {}}}
	delay := func(base time.Duration) bool {
		e := r.entries["dead"]
		d := e.Next.Sub(e.CheckedAt)
		return d >= base && d <= base+nodeReadinessJitter
	}
	// No measured control yet: a refused TCP connect may be our own uplink.
	r.observeLocked("dead", transport, at)
	if e := r.entries["dead"]; e.Failures != 0 || e.Transport != 0 || !r.pausedUntil.Equal(at.Add(nodeReadinessShortPause)) {
		t.Fatalf("uncontrolled transport failure penalized the node %+v", e)
	}
	r.observeLocked("good", pass, at.Add(time.Minute))
	r.observeLocked("dead", transport, at.Add(2*time.Minute))
	if e := r.entries["dead"]; e.Failures != 1 || e.Transport != 1 || e.failing(at.Add(2*time.Minute)) || !delay(nodeReadinessRecheck) {
		t.Fatalf("first controlled transport failure %+v", e)
	}
	// A repeat inside ten minutes (an explicit job) is the same episode.
	r.observeLocked("dead", transport, at.Add(5*time.Minute))
	if e := r.entries["dead"]; e.Failures != 1 {
		t.Fatalf("repeat within ten minutes counted %+v", e)
	}
	r.observeLocked("good", pass, at.Add(11*time.Minute))
	r.observeLocked("dead", transport, at.Add(12*time.Minute))
	if e := r.entries["dead"]; e.Failures != 2 || e.Transport != 2 || !e.failing(at.Add(12*time.Minute)) || !delay(nodeReadinessDeadBackoff) {
		t.Fatalf("second TCP failure must start the long backoff %+v", e)
	}
	next := at.Add(12 * time.Minute)
	for _, want := range []time.Duration{2 * nodeReadinessDeadBackoff, nodeReadinessMaxBackoff, nodeReadinessMaxBackoff} {
		next = next.Add(want + nodeReadinessJitter)
		r.observeLocked("good", pass, next.Add(-time.Minute))
		r.observeLocked("dead", transport, next)
		if !delay(want) {
			t.Fatalf("backoff %s, want %s", r.entries["dead"].Next.Sub(next), want)
		}
	}
	// An egress failure ends the TCP streak; the ordinary backoff applies.
	next = next.Add(nodeReadinessMaxBackoff + nodeReadinessJitter)
	r.observeLocked("dead", egress, next)
	if e := r.entries["dead"]; e.Transport != 0 || e.Failures != 6 || !delay(16*nodeReadinessBackoff) {
		t.Fatalf("egress after TCP streak %+v", e)
	}
	r.observeLocked("dead", pass, next.Add(time.Hour))
	if e := r.entries["dead"]; e.Failures != 0 || e.Transport != 0 || !e.ready(next.Add(time.Hour)) || e.failing(next.Add(time.Hour)) {
		t.Fatalf("PASS did not reset %+v", e)
	}
	// Outcomes that say nothing about the node never count against it.
	for _, item := range []nodeCheckItem{
		{Engine: "sing-box", Stage: "egress", Verdict: "INCONCLUSIVE", ErrorCode: "node-direct-control-unavailable", DirectControl: "unavailable", CleanupVerified: true},
		{Engine: "sing-box", Stage: "connectivity", Verdict: "ERROR", ErrorCode: "node-connectivity-request-failed", DirectControl: "measured", CleanupVerified: true},
		{ErrorCode: "node-check-busy"},
		{ErrorCode: "node-check-canceled"},
		{ErrorCode: "node-network-changed"},
		{Engine: "sing-box", Stage: "egress", Verdict: "ERROR", ErrorCode: "node-egress-failed", DirectControl: "measured"}, // cleanup not verified
	} {
		before := r.entries["good"]
		r.observeLocked("good", item, next.Add(2*time.Hour))
		if e := r.entries["good"]; e.Failures != before.Failures || e.failing(next.Add(2*time.Hour)) {
			t.Fatalf("%s penalized a node %+v", item.ErrorCode, e)
		}
	}
	r.observeLocked("good", nodeCheckItem{Stage: "cleanup", ErrorCode: "node-cleanup-failed"}, next.Add(3*time.Hour))
	if !r.halted {
		t.Fatal("unverified cleanup did not stop the rotation")
	}
}

func TestNodeReadinessWANFailurePausesWithoutPenalty(t *testing.T) {
	a, ids, _, checker, _, start := readinessFixture(t)
	ctx := context.Background()
	checker.outcome = func(id string) string {
		if id == ids[0] {
			return "wan"
		}
		return "pass"
	}
	at := start.Add(time.Minute)
	a.nodeReadinessRound(ctx, at)
	if checker.count() != 1 || a.nodeReadinessSnapshot(at).State != "paused-network" {
		t.Fatal("WAN failure did not pause", checker.calls, a.nodeReadinessSnapshot(at))
	}
	for _, offset := range []time.Duration{time.Minute, 4 * time.Minute} {
		if a.nodeReadinessRound(ctx, at.Add(offset)); checker.count() != 1 {
			t.Fatal("rotation continued during the WAN pause")
		}
	}
	if e := readinessEntry(a, ids[0]); e.Failures != 0 || e.failing(at) {
		t.Fatalf("WAN failure penalized the node %+v", e)
	}
	if order := a.nodeReadinessOrder(slices.Clone(ids), "sing-box", "wan-0123456789ab", true, at.Add(time.Minute)); !reflect.DeepEqual(order, ids) {
		t.Fatal("WAN failure changed the candidate order", order)
	}
	a.nodeReadinessRound(ctx, at.Add(nodeReadinessWANPause+time.Second))
	if checker.count() != 2 || checker.last() != ids[1] {
		t.Fatal("rotation did not resume after the pause", checker.calls)
	}
}

func readinessWriteConfig(t *testing.T, a *App, mutate func(*config.Config)) {
	t.Helper()
	cfg := a.Store.Get()
	mutate(&cfg)
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if a.Store, err = config.Load(path); err != nil {
		t.Fatal(err)
	}
}

func TestNodeReadinessRunsOnlyWhenAutopilotCouldUseANode(t *testing.T) {
	for _, scenario := range []string{"allowed", "safe-mode", "stopped", "manual", "autopilot-paused", "user-operation", "stop-due", "no-node-service", "no-source", "no-connectivity-checker"} {
		t.Run(scenario, func(t *testing.T) {
			a, _, _, checker, _, start := readinessFixture(t)
			ctx := context.Background()
			switch scenario {
			case "safe-mode":
				readinessWriteConfig(t, a, func(c *config.Config) { c.SafeMode = true })
			case "stopped":
				readinessWriteConfig(t, a, func(c *config.Config) {
					c.ServiceControl.Stopped = true
					c.AppliedServices = map[string]config.ServiceState{}
				})
			case "manual":
				readinessWriteConfig(t, a, func(c *config.Config) { c.ServiceControl.Mode = "manual" })
			case "autopilot-paused":
				a.autonomy.doc.Policy.Enabled = false
			case "user-operation":
				release, err := a.Operations.Enter(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			case "stop-due":
				a.reconciler.started = true
				a.reconciler.doc.Jobs = []durableServiceJob{{Request: serviceControlJobRequest{Kind: "stop"}, State: "queued"}}
			case "no-node-service":
				s := a.autonomy.doc.Services["my-independent-site"]
				s.Enabled = false
				a.autonomy.doc.Services["my-independent-site"] = s
			case "no-source":
				a.autonomy.doc.Policy.SourceIDs = []string{}
			case "no-connectivity-checker":
				a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
					panic("service check")
				})
			}
			a.nodeReadinessRound(ctx, start.Add(time.Minute))
			want := 0
			if scenario == "allowed" {
				want = 1
			}
			if checker.count() != want {
				t.Fatalf("checks %d, want %d", checker.count(), want)
			}
		})
	}
}

func TestNodeReadinessOrderMovesFreshPassFirstAndRepeatedFailuresLast(t *testing.T) {
	now := time.Now().UTC()
	a := &App{}
	a.nodeReadiness.network = "wan-one"
	a.nodeReadiness.entries = map[string]nodeReadinessEntry{
		"n0": {Engine: "sing-box", CheckedAt: now.Add(-time.Minute), Failures: 2, LastFailure: now.Add(-time.Minute)},
		"n1": {Engine: "sing-box", CheckedAt: now.Add(-time.Minute), Failures: 1, LastFailure: now.Add(-time.Minute)},
		"n2": {Engine: "sing-box", CheckedAt: now.Add(-time.Minute), Ready: true, PassAt: now.Add(-time.Minute)},
		"n3": {Engine: "sing-box", CheckedAt: now.Add(-time.Hour), Ready: true, PassAt: now.Add(-time.Hour)},
		"x4": {Engine: "xray", CheckedAt: now.Add(-time.Minute), Ready: true, PassAt: now.Add(-time.Minute)},
	}
	ids := []string{"n0", "n1", "n2", "n3", "x4", "n5"}
	before := slices.Clone(ids)
	if got := a.nodeReadinessOrder(ids, "sing-box", "wan-one", true, now); !reflect.DeepEqual(got, []string{"n2", "x4", "n1", "n3", "n5", "n0"}) {
		t.Fatal("AUTO order", got)
	}
	if got := a.nodeReadinessOrder(ids, "sing-box", "wan-one", false, now); !reflect.DeepEqual(got, []string{"n2", "n1", "n3", "x4", "n5", "n0"}) {
		t.Fatal("an Xray observation ordered a Sing-box search", got)
	}
	if got := a.nodeReadinessOrder(ids, "sing-box", "wan-two", true, now); !reflect.DeepEqual(got, ids) {
		t.Fatal("another network's observations were used", got)
	}
	if !reflect.DeepEqual(ids, before) {
		t.Fatal("input changed")
	}
}

// The autopilot's first-usable search checks a node with a fresh pool PASS
// first. The search still proves the service afresh before Apply.
func TestNodeReadinessOrdersAutopilotSearch(t *testing.T) {
	for _, pool := range []bool{false, true} {
		t.Run(map[bool]string{false: "without-pool", true: "with-pool"}[pool], func(t *testing.T) {
			a, ids, _ := autonomousIntegrationFixture(t)
			now := time.Now().UTC()
			if pool {
				a.nodeReadiness.network = "wan-0123456789ab"
				a.nodeReadiness.entries = map[string]nodeReadinessEntry{
					ids[0]: {Engine: "sing-box", CheckedAt: now.Add(-time.Minute), Failures: 2, LastFailure: now.Add(-time.Minute)},
					ids[1]: {Engine: "sing-box", CheckedAt: now.Add(-time.Minute), Ready: true, PassAt: now.Add(-time.Minute)},
				}
			}
			var checked []string
			a.NodeChecker = jobNodeChecker(func(_ context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked = append(checked, q.NodeID)
				return d10Result(q, "sing-box", true), nil
			})
			a.autonomyRound(context.Background(), time.Now())
			want := ids[0]
			if pool {
				want = ids[1]
			}
			if len(checked) == 0 || checked[0] != want || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+want {
				t.Fatal("search order", checked, autonomyTestState(a).State)
			}
		})
	}
}

// The pool runs on the reconciler's existing feeds cadence after the
// autopilot round, with no new operation kind in the scheduler journal.
func TestNodeReadinessRunsFromReconcilerFeedsTask(t *testing.T) {
	a, ids, _, checker, _, _ := readinessFixture(t)
	now := time.Now()
	initReconcilerFixture(t, a, now)
	a.reconciler.mu.Lock()
	for _, kind := range []string{"node-fallback", "service-checks"} {
		a.reconciler.doc.Operations = append(a.reconciler.doc.Operations, automationOperation{Kind: kind, State: "completed", Reason: "scheduled", ConfigFingerprint: automationConfigFingerprint(a.Store.Get()), NextRun: now.Add(time.Hour)})
	}
	for i := range a.reconciler.doc.Operations {
		if a.reconciler.doc.Operations[i].Kind == "feeds" {
			a.reconciler.doc.Operations[i].NextRun = now.Add(-time.Second)
		}
	}
	a.reconciler.mu.Unlock()
	// The autopilot round has nothing due, so it makes no service check.
	a.autonomy.mu.Lock()
	r := a.autonomy.doc.Runtime["my-independent-site"]
	r.NextCheck = now.Add(time.Hour)
	a.autonomy.doc.Runtime["my-independent-site"] = r
	a.autonomy.mu.Unlock()
	a.reconcileRound(context.Background(), time.Now())
	if checker.count() != 1 || checker.last() != ids[0] {
		t.Fatal("feeds task did not run one readiness check", checker.calls)
	}
	a.reconciler.mu.Lock()
	defer a.reconciler.mu.Unlock()
	kinds := []string{}
	for _, op := range a.reconciler.doc.Operations {
		kinds = append(kinds, op.Kind)
	}
	slices.Sort(kinds)
	if !reflect.DeepEqual(kinds, []string{"feeds", "legacy-routes", "node-fallback", "node-recovery", "service-checks"}) {
		t.Fatal("scheduler journal changed shape", kinds)
	}
}

// Xray is allowed but no permitted node needs it: three fresh Sing-box PASS
// nodes still stop exploration, and the fourth node is never contacted.
func TestNodeReadinessWarmIgnoresAnEngineNoNodeNeeds(t *testing.T) {
	a, ids, _, checker, _, start := readinessFixture(t)
	a.NodeCheckers = map[string]dataplane.NodeChecker{"sing-box": checker, "xray": &readinessChecker{}}
	a.autonomy.doc.Policy.PreferredRoutes = []string{"sing-box", "xray"}
	at := start.Add(time.Minute)
	for i, offset := range []time.Duration{0, 31 * time.Second, 62 * time.Second, 93 * time.Second, 124 * time.Second, 155 * time.Second} {
		a.nodeReadinessRound(context.Background(), at.Add(offset))
		if want := min(i+1, 3); checker.count() != want {
			t.Fatalf("tick %d: %d checks, want %d: %v", i, checker.count(), want, checker.calls)
		}
	}
	if e := readinessEntry(a, ids[3]); e.Engine != "sing-box" || !e.CheckedAt.IsZero() {
		t.Fatalf("fourth node %+v", e)
	}
	if view := a.nodeReadinessSnapshot(at.Add(155 * time.Second)); view.State != "warm" || view.Ready != 3 || view.Unchecked != 1 {
		t.Fatalf("status %+v", view)
	}
}
