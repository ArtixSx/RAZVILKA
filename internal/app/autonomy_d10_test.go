package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

func d10Result(request dataplane.NodeCheckRequest, engine string, pass bool) dataplane.NodeCheckResult {
	r := autofallbackResult(request, pass)
	r.RoutePathID = engine + ":" + request.NodeID
	if !pass {
		r.Verdict, r.HTTPStatus, r.ErrorCode = evidence.VerdictBlocked, 403, "http-403"
	}
	return modeledNodeServiceProof(r, engine)
}

func d10Options(a *App, ids []string) {
	a.nodeReviews.options = func() []routecatalog.Option {
		out := []routecatalog.Option{{ID: "direct", Installed: true, Configured: true, Selectable: true}, {ID: "sing-box", Installed: true, Configured: true, Selectable: true}}
		for _, id := range ids {
			out = append(out, routecatalog.Option{ID: "sing-box:" + id, Installed: true, Configured: true, Selectable: true, Services: []string{"my-independent-site", "telegram"}})
		}
		return out
	}
}

func d10Reopen(t *testing.T, a *App) {
	t.Helper()
	a.autonomy.mu.Lock()
	a.autonomy.loaded = false
	a.autonomy.mu.Unlock()
	if err := a.loadAutonomy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Real app worker, stores, compiler and transaction journal; checker and OS
// adapter are controlled. This does not assert native route/LAN acceptance.
func TestD10ColdAppliesFirstUsableBeforeNextCheck(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	checked := []string{}
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		if len(checked) > 1 {
			t.Fatal("C checked before first usable B was applied")
		}
		return d10Result(req, "sing-box", true), nil
	})
	adapter.after = func(phase string) error {
		if phase == "stage" {
			data, err := os.ReadFile(a.autonomy.path)
			if err != nil {
				t.Fatal(err)
			}
			d, err := decodeAutonomy(data)
			if err != nil {
				t.Fatal(err)
			}
			r := d.Runtime["my-independent-site"]
			if r.Search.Cursor != 1 || !r.Search.Halted || len(r.Switches) != 1 {
				t.Fatal("Apply preceded durable consumption/budget/intent", r)
			}
		}
		return nil
	}
	a.autonomyRound(context.Background(), time.Now())
	r := autonomyTestState(a)
	if r.State != "applied" || !reflect.DeepEqual(checked, ids[:1]) || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+ids[0] || !slices.Contains(adapter.calls, "commit") {
		t.Fatal(r, checked, adapter.calls)
	}
}

func TestD10ColdVerifiedRollbackRequiresFreshNextCheck(t *testing.T) {
	a, ids, old := autonomousIntegrationFixture(t)
	adapter := &candidateApplyAdapter{nodeApplyAdapter: old}
	a.Dataplane.Adapters["sing-box"] = adapter
	adapter.health = func(p dataplane.Plan) error {
		if f := candidateFailureForTest(p, ids[0]); f != nil {
			return f
		}
		return nil
	}
	checked := []string{}
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		if req.NodeID == ids[1] && !slices.Contains(old.calls, "verify-rollback") {
			t.Fatal("next check preceded verified rollback")
		}
		return d10Result(req, "sing-box", true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	r := autonomyTestState(a)
	if r.State != "applied" || !reflect.DeepEqual(checked, ids) || len(r.CandidateFailures) != 1 || r.CandidateFailures[0].NodeID != ids[0] || len(r.Switches) != 2 || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+ids[1] {
		t.Fatal(r, checked, old.calls)
	}
}

func TestD10UntrustedApplyRemainsHaltedAfterRestart(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	before := a.Store.Get()
	adapter.after = func(phase string) error {
		if phase == "health" {
			return errors.New("unattributed failure")
		}
		return nil
	}
	checked := []string{}
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		return d10Result(req, "sing-box", true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	if r := autonomyTestState(a); r.State != "apply-refused" || !r.Search.Halted || len(r.CandidateFailures) != 0 || !reflect.DeepEqual(checked, ids[:1]) || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal(r, checked)
	}
	d10Reopen(t, a)
	checked = nil
	adapter.calls = nil
	a.autonomyRound(context.Background(), time.Now())
	if r := autonomyTestState(a); r.State != "requires-review" || len(checked) != 0 || len(adapter.calls) != 0 {
		t.Fatal("restart continued uncertain Apply", r, checked)
	}
}

func TestD10CursorWriteFailureCannotApplyOrPenalize(t *testing.T) {
	a, _, adapter := autonomousIntegrationFixture(t)
	before := a.Store.Get()
	var lease *restorejournal.FileTarget
	defer func() {
		if lease != nil {
			_ = lease.Close()
		}
	}()
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		var err error
		lease, err = restorejournal.OpenFileTarget(a.autonomy.path)
		if err != nil {
			t.Fatal(err)
		}
		return d10Result(req, "sing-box", true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	r := autonomyTestState(a)
	if r.State != "requires-review" || len(adapter.calls) != 0 || len(r.Switches) != 0 || len(r.CandidateFailures) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal(r, adapter.calls)
	}
}

func TestD10LocalErrorsDoNotConsumeOrApply(t *testing.T) {
	for _, scenario := range []string{"busy", "runtime", "cleanup", "cancel", "inconclusive", "error-verdict", "unsupported-with-local-error", "stopped", "safe-mode"} {
		t.Run(scenario, func(t *testing.T) {
			a, _, adapter := autonomousIntegrationFixture(t)
			if scenario == "stopped" {
				// Give Stop an existing enabled applied route to suspend.
				if _, err := a.Store.ApplyAutonomyRouteWithRollback("telegram", "sing-box", []string{"192.168.1.2/32"}, a.Store.Get().Revision); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checked := 0
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked++
				r := d10Result(req, "sing-box", true)
				switch scenario {
				case "busy":
					return r, dataplane.ErrExactNodeBusy
				case "runtime":
					return r, dataplane.ErrExactNodeRuntime
				case "cleanup":
					r.ErrorCode = "node-cleanup-failed"
					return r, errors.New("cleanup uncertain")
				case "cancel":
					cancel()
					return r, context.Canceled
				case "inconclusive":
					r.Available = false
					r.Verdict = evidence.VerdictInconclusive
				case "error-verdict":
					r.Available = false
					r.Verdict = evidence.VerdictError
				case "unsupported-with-local-error":
					return r, errors.Join(dataplane.ErrExactNodeUnsupported, dataplane.ErrExactNodeRuntime)
				case "stopped":
					if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"telegram": "sing-box"}, a.Store.Get().Revision); err != nil {
						t.Fatal(err)
					}
				case "safe-mode":
					if err := a.Store.SetSafeMode(true); err != nil {
						t.Fatal(err)
					}
				}
				return r, nil
			})
			a.autonomyRound(ctx, time.Now())
			r := autonomyTestState(a)
			if checked != 1 || len(adapter.calls) != 0 || r.Search == nil || r.Search.Cursor != 0 || len(r.CandidateFailures) != 0 || r.State == "applied" {
				t.Fatal(r, checked, adapter.calls)
			}
		})
	}
}

func TestD10UnsupportedCursorSurvivesRestartAndAppendsNewPage(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.CandidatesPerRound = 1
	err := a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	checked := []string{}
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		return dataplane.NodeCheckResult{}, dataplane.ErrExactNodeUnsupported
	})
	a.autonomyRound(context.Background(), time.Now())
	d10Reopen(t, a)
	a.autonomyRound(context.Background(), time.Now())
	if r := autonomyTestState(a); !r.Search.Exhausted || r.Search.Cursor != 2 || !reflect.DeepEqual(checked, ids) {
		t.Fatal(r, checked)
	}
	snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174009@new-page.example:443?security=tls", time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	newID := ""
	for _, n := range snapshot.Nodes {
		if !slices.Contains(ids, n.ID) {
			newID = n.ID
		}
	}
	d10Options(a, append(ids, newID))
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		return d10Result(req, "sing-box", true), nil
	})
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Now())
	if r := autonomyTestState(a); r.State != "applied" || !reflect.DeepEqual(checked, append(ids, newID)) || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+newID || !slices.Contains(adapter.calls, "commit") {
		t.Fatal(r, checked)
	}
	snapshot, err = a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range snapshot.Nodes {
		if slices.Contains(ids, n.ID) {
			for _, c := range n.Health.History {
				if c.ServiceID == "my-independent-site" {
					t.Fatal("unsupported wrote history", n.ID)
				}
			}
		}
	}
}

func TestD10Worker32UnsupportedQueuesRefillThenAppliesEntry33(t *testing.T) {
	a, _, adapter := autonomousIntegrationFixture(t)
	feedRoot := filepath.Join(t.TempDir(), "feeds")
	if err := os.Mkdir(feedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	feeds, err := providerfeed.Open(a.Nodes, feedRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer feeds.Close()
	source, err := feeds.Save(context.Background(), "", providerfeed.SaveRequest{Request: providerfeed.Request{URL: "https://feed.example.org/approved", Limit: 32}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	a.NodeFeeds = feeds
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.SourceIDs = []string{source.SourceID}
	a.autonomy.doc.Policy.CandidatesPerRound = 4
	err = a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	profiles := []string{}
	for i := 0; i < 32; i++ {
		profiles = append(profiles, fmt.Sprintf("vless://123e4567-e89b-12d3-a456-426614174000@page%d.example:443?security=tls", i))
	}
	_, err = a.Nodes.Import(context.Background(), nodestore.Source{ID: source.SourceID, Kind: "subscription"}, strings.Join(profiles, "\n"), time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		waitCtx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := feeds.Wait(waitCtx); err != nil {
			t.Error(err)
		}
	}()
	// The real passive worker queue is exercised; network admission is held.
	// The imported page below models the completed approved publisher handoff.
	feeds.StartManaged(ctx, func(c context.Context) (func(), error) { <-c.Done(); return nil, c.Err() })
	checked := []string{}
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		return dataplane.NodeCheckResult{}, dataplane.ErrExactNodeUnsupported
	})
	for i := 0; i < 8; i++ {
		autonomyTestDue(a, false)
		a.autonomyRound(context.Background(), time.Now())
		a.autonomy.mu.Lock()
		refill := a.autonomy.refillState
		a.autonomy.mu.Unlock()
		if i < 7 && refill.State == "queued" {
			t.Fatal("next page requested before exhausting stable snapshot")
		}
	}
	r := autonomyTestState(a)
	a.autonomy.mu.Lock()
	refill := a.autonomy.refillState
	a.autonomy.mu.Unlock()
	if !r.Search.Exhausted || len(checked) != 32 || refill.State != "queued" || refill.SourceID != source.SourceID || len(adapter.calls) != 0 {
		t.Fatal(r, len(checked), refill)
	}
	d10Reopen(t, a)
	snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: source.SourceID, Kind: "subscription"}, "vless://123e4567-e89b-12d3-a456-426614174000@entry33.example:443?security=tls", time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	newID := ""
	for _, n := range snapshot.Nodes {
		if allowedAutonomyNode(a.autonomyPolicy(), n, time.Now()) && !slices.Contains(checked, n.ID) {
			newID = n.ID
		}
	}
	d10Options(a, []string{newID})
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		if req.NodeID != newID {
			t.Fatal("consumed prefix repeated", req.NodeID)
		}
		checked = append(checked, req.NodeID)
		return d10Result(req, "sing-box", true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	if r = autonomyTestState(a); r.State != "applied" || len(checked) != 33 || r.Search.Cursor != 33 || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+newID {
		t.Fatal(r, len(checked))
	}
}

func TestD10RestartTailDoesNotWrapIntoConsumedPrefix(t *testing.T) {
	for _, total := range []int{3, 32} {
		t.Run(fmt.Sprintf("nodes%d", total), func(t *testing.T) {
			a, _, adapter := autonomousIntegrationFixture(t)
			profiles := []string{}
			for i := 2; i < total; i++ {
				profiles = append(profiles, fmt.Sprintf("vless://123e4567-e89b-12d3-a456-426614174000@tail%d.example:443?security=tls", i))
			}
			snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, strings.Join(profiles, "\n"), time.Now(), time.Hour, false)
			if err != nil {
				t.Fatal(err)
			}
			ids := []string{}
			for _, node := range snapshot.Nodes {
				ids = append(ids, node.ID)
			}
			slices.Sort(ids)
			if len(ids) != total {
				t.Fatal("wrong catalogue size", len(ids))
			}
			a.autonomy.mu.Lock()
			a.autonomy.doc.Policy.CandidatesPerRound = 2
			p := a.autonomy.doc.Policy
			s := a.autonomy.doc.Services["my-independent-site"]
			r := a.autonomy.doc.Runtime[s.ID]
			r.Search = &autonomy.Traversal{Version: autonomyTraversalVersion(p, s, "sing-box", "wan-0123456789ab"), Ordered: slices.Clone(ids), Cursor: total - 1}
			a.autonomy.doc.Runtime[s.ID] = r
			err = a.persistAutonomyLocked(context.Background())
			a.autonomy.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			d10Reopen(t, a)
			checked := []string{}
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked = append(checked, req.NodeID)
				return dataplane.NodeCheckResult{}, dataplane.ErrExactNodeUnsupported
			})
			a.autonomyRound(context.Background(), time.Now())
			r = autonomyTestState(a)
			if !reflect.DeepEqual(checked, ids[total-1:]) || r.Search.Cursor != total || !r.Search.Exhausted || len(adapter.calls) != 0 {
				t.Fatal("tail wrapped consumed prefix", r, checked)
			}
			d10Reopen(t, a)
			checked = nil
			a.autonomyRound(context.Background(), time.Now())
			if r = autonomyTestState(a); len(checked) != 0 || r.Search.Cursor != total || !r.Search.Exhausted {
				t.Fatal("restart lost exhausted tail", r, checked)
			}
			// A finished passive page is appended after the consumed tail;
			// its single usable entry can apply despite the round budget being2.
			snapshot, err = a.Nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@after-tail.example:443?security=tls", time.Now(), time.Hour, false)
			if err != nil {
				t.Fatal(err)
			}
			newID := ""
			for _, node := range snapshot.Nodes {
				if !slices.Contains(ids, node.ID) {
					newID = node.ID
				}
			}
			d10Options(a, []string{newID})
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked = append(checked, req.NodeID)
				return d10Result(req, "sing-box", true), nil
			})
			autonomyTestDue(a, false)
			a.autonomyRound(context.Background(), time.Now())
			if r = autonomyTestState(a); r.State != "applied" || !reflect.DeepEqual(checked, []string{newID}) || r.Search.Cursor != total+1 || !r.Search.Exhausted {
				t.Fatal("page after tail repeated prefix", r, checked)
			}
		})
	}
}

func TestD10TraversalValidationAndRestartStableOrdering(t *testing.T) {
	ids := []string{"node-" + strings.Repeat("1", 64), "node-" + strings.Repeat("2", 64)}
	r := autonomy.Runtime{}
	version := strings.Repeat("a", 64)
	prepareAutonomyTraversal(&r, version, ids, time.Now())
	r.Search.Cursor = 1
	copy := r.Clone()
	copy.Search.Ordered[0] = "changed"
	if r.Search.Ordered[0] != ids[0] {
		t.Fatal("clone shares ordering")
	}
	newID := "node-" + strings.Repeat("0", 64)
	prepareAutonomyTraversal(&r, version, []string{newID, ids[1], ids[0]}, time.Now())
	if !reflect.DeepEqual(r.Search.Ordered, append(ids, newID)) || r.Search.Cursor != 1 {
		t.Fatal(r.Search)
	}
	p := autonomy.Default()
	s := autonomy.Service{ID: "example", Definition: strings.Repeat("a", 64), DraftFingerprint: strings.Repeat("b", 64), Sources: []string{"192.168.1.1/32"}}
	d := newAutonomyDocument()
	d.Policy = p
	d.Services[s.ID] = s
	d.Runtime[s.ID] = r
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeAutonomy(data); err != nil {
		t.Fatal(err)
	}
	r.Search.Cursor = 4
	d.Runtime[s.ID] = r
	data, _ = json.Marshal(d)
	if _, err := decodeAutonomy(data); err == nil {
		t.Fatal("out-of-bounds cursor accepted")
	}
	r.Search.Cursor = 1
	r.Search.Halted = true
	r.Search.Exhausted = false
	r.Search.RetryAt = time.Now().Add(-time.Hour)
	prepareAutonomyTraversal(&r, version, ids, time.Now())
	if !r.Search.Halted {
		t.Fatal("retry cleared untrusted Apply latch")
	}
	r.Search.Halted = false
	r.Search.Cursor = len(r.Search.Ordered)
	r.Search.Exhausted = true
	r.Search.RetryAt = time.Now().Add(-time.Hour)
	fresh := "node-" + strings.Repeat("3", 64)
	prefix := len(r.Search.Ordered)
	prepareAutonomyTraversal(&r, version, append(r.Search.Ordered, fresh), time.Now())
	if r.Search.Cursor != prefix || r.Search.Ordered[prefix] != fresh || r.Search.Exhausted {
		t.Fatal("late page restarted old prefix", r.Search)
	}
}

func TestD10XrayUsesExactCheckerAndPreservesApplyGate(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	a.autonomy.mu.Lock()
	s := a.autonomy.doc.Services["my-independent-site"]
	s.ExpectedRoute = "xray"
	a.autonomy.doc.Services[s.ID] = s
	err := a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		t.Fatal("Sing-box used for Xray intent")
		return dataplane.NodeCheckResult{}, nil
	})
	checked := []string{}
	a.NodeCheckers = map[string]dataplane.NodeChecker{"xray": jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		return d10Result(req, "xray", true), nil
	})}
	admissions := 0
	a.NodeHistoryWriteGuard = func(_ context.Context, reader int) error {
		admissions++
		if reader != 2 {
			t.Fatal("wrong history admission version", reader)
		}
		return nil
	}
	before := a.Store.Get()
	a.autonomyRound(context.Background(), time.Now())
	r := autonomyTestState(a)
	if admissions < 1 || !reflect.DeepEqual(checked, ids[:1]) || r.State == "applied" || !reflect.DeepEqual(before, a.Store.Get()) || len(adapter.calls) != 0 {
		t.Fatal("engine proof or gate bypass", r, checked, adapter.calls)
	}
	snapshot, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range snapshot.Nodes {
		for _, c := range n.Health.History {
			if c.ServiceID == s.ID && c.RoutePathID != "xray:"+n.ID {
				t.Fatal("Xray observation relabeled", c)
			}
		}
	}
}
