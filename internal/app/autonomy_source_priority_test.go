package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
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

func sourcePriorityImport(t *testing.T, a *App, node, source, newHost string) []string {
	t.Helper()
	var snapshot nodestore.Snapshot
	err := a.Nodes.WithSecret(context.Background(), node, func(raw []byte) error {
		var outbound map[string]any
		if err := json.Unmarshal(raw, &outbound); err != nil {
			return err
		}
		if newHost != "" {
			outbound["server"] = newHost
		}
		data, err := json.Marshal(map[string]any{"outbounds": []any{outbound}})
		if err != nil {
			return err
		}
		defer clear(data)
		kind := "subscription"
		if source == "manual" {
			kind = "manual"
		}
		snapshot, err = a.Nodes.Import(context.Background(), nodestore.Source{ID: source, Kind: kind}, string(data), time.Now(), time.Hour, false)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, node := range snapshot.Nodes {
		ids = append(ids, node.ID)
	}
	slices.Sort(ids)
	return ids
}

func sourcePriorityPolicy(t *testing.T, a *App, limit int) {
	t.Helper()
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.SourceIDs = []string{"manual", "priority"}
	a.autonomy.doc.Policy.PreferredSourceIDs = []string{"priority"}
	a.autonomy.doc.Policy.CandidatesPerRound = limit
	err := a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}

func sourcePriorityProber(a *App, calls *[]string) {
	options := a.nodeReviews.options
	a.nodeReviews.options = func() []routecatalog.Option {
		return append(options(), routecatalog.Option{ID: "warp-wg", Installed: true, Configured: true, Running: true, Selectable: true, Ready: true})
	}
	a.TestLab = testlab.NewRunner()
	a.RouteProber = autonomyResourceRouteProber(func(_ context.Context, service catalog.Service, route string) testlab.Result {
		*calls = append(*calls, route)
		return testlab.Result{ServiceID: service.ID, Route: route, Status: "not-ready", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	})
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.PreferredRoutes = []string{"warp-wg"}
	a.autonomy.mu.Unlock()
}

func TestAutonomySourcePrioritySharesBudgetAndResumesBeforeStandard(t *testing.T) {
	a, preferred, adapter := autonomousIntegrationFixture(t)
	sourcePriorityImport(t, a, preferred[0], "priority", "")
	sourcePriorityImport(t, a, preferred[1], "priority", "")
	all := sourcePriorityImport(t, a, preferred[0], "manual", "third.example")
	public := ""
	for _, id := range all {
		if !slices.Contains(preferred, id) {
			public = id
		}
	}
	d10Options(a, all)
	var probes, checked []string
	sourcePriorityProber(a, &probes)
	sourcePriorityPolicy(t, a, 1)
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		return d10Result(req, "sing-box", req.NodeID == public), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	first := autonomyTestState(a)
	if len(checked) != 1 || !slices.Contains(preferred, checked[0]) || len(probes) != 0 || first.Search.Cursor != 1 || first.Search.StandardRoutesTried {
		t.Fatal("standard phase preceded remaining priority prefix", first, checked, probes)
	}
	d10Reopen(t, a)
	a.autonomyRound(context.Background(), time.Now())
	second := autonomyTestState(a)
	if len(checked) != 2 || checked[1] == checked[0] || !slices.Contains(preferred, checked[1]) || !slices.Equal(probes, []string{"warp-wg"}) || second.Search.Cursor != 2 || !second.Search.StandardRoutesTried {
		t.Fatal("priority resume reset its prefix or gained a second node budget", second, checked, probes)
	}
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Now())
	final := autonomyTestState(a)
	if final.State != "applied" || len(checked) != 3 || checked[2] != public || len(probes) != 1 || !slices.Contains(adapter.calls, "commit") {
		t.Fatal("public tail starved or failed fresh Apply", final, checked, probes, adapter.calls)
	}
}

func TestAutonomySourcePriorityRollbackBeforePublicCheck(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		t.Run(map[bool]string{true: "verified", false: "unattributed"}[trusted], func(t *testing.T) {
			a, ids, old := autonomousIntegrationFixture(t)
			sourcePriorityImport(t, a, ids[1], "priority", "")
			var probes, checked []string
			sourcePriorityProber(a, &probes)
			sourcePriorityPolicy(t, a, 2)
			adapter := &candidateApplyAdapter{nodeApplyAdapter: old}
			a.Dataplane.Adapters["sing-box"] = adapter
			adapter.health = func(p dataplane.Plan) error {
				if f := candidateFailureForTest(p, ids[1]); f != nil {
					if trusted {
						return f
					}
					return errors.New("unattributed runtime failure")
				}
				return nil
			}
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked = append(checked, req.NodeID)
				if req.NodeID == ids[0] && !slices.Contains(old.calls, "verify-rollback") {
					t.Fatal("public candidate checked before full rollback verification")
				}
				return d10Result(req, "sing-box", true), nil
			})
			a.autonomyRound(context.Background(), time.Now())
			r := autonomyTestState(a)
			if !trusted {
				if !r.Search.Halted || !slices.Equal(checked, ids[1:]) || len(probes) != 0 || len(r.CandidateFailures) != 0 {
					t.Fatal("uncertain rollback crossed priority boundary", r, checked, probes)
				}
				return
			}
			if r.State != "applied" || !slices.Equal(checked, []string{ids[1], ids[0]}) || len(probes) != 1 || len(r.Switches) != 2 || len(r.CandidateFailures) != 1 {
				t.Fatal("verified rollback lost shared counters/fresh next check", r, checked, probes)
			}
		})
	}
}

func TestAutonomySourcePriorityKeepsHealthyCurrent(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return d10Result(req, "sing-box", true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	before := a.Store.Get()
	sourcePriorityImport(t, a, ids[1], "priority", "")
	sourcePriorityPolicy(t, a, 2)
	adapter.calls = nil
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Now())
	if !reflect.DeepEqual(before, a.Store.Get()) || slices.Contains(adapter.calls, "activate") || slices.Contains(adapter.calls, "commit") {
		t.Fatal("priority replaced a healthy incumbent", adapter.calls)
	}
}

func TestAutonomyPriorityBoundaryCannotResetSwitchBudget(t *testing.T) {
	a, ids, old := autonomousIntegrationFixture(t)
	sourcePriorityImport(t, a, ids[1], "priority", "")
	sourcePriorityPolicy(t, a, 2)
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.MaxSwitchesPerHour = 1
	err := a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	adapter := &candidateApplyAdapter{nodeApplyAdapter: old}
	a.Dataplane.Adapters["sing-box"] = adapter
	adapter.health = func(p dataplane.Plan) error {
		if f := candidateFailureForTest(p, ids[1]); f != nil {
			return f
		}
		return nil
	}
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return d10Result(req, "sing-box", true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	r := autonomyTestState(a)
	if r.State != "rate-limited" || r.Search.Halted || len(r.Switches) != 1 || len(r.CandidateFailures) != 1 || slices.Contains(old.calls, "commit") || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("standard tail reset the priority phase switch budget", r, old.calls)
	}
}

func TestAutonomySourceRankNeedsFreshConsentedOrigin(t *testing.T) {
	now := time.Now()
	p := autonomy.Policy{SourceIDs: []string{"manual", "first", "second"}, PreferredSourceIDs: []string{"second", "first"}}
	for _, tc := range []struct {
		name, source string
		start, end   time.Time
		want         int
	}{
		{"ordered-second", "second", now.Add(-time.Minute), now.Add(time.Minute), 0},
		{"ordered-first", "first", now.Add(-time.Minute), now.Add(time.Minute), 1},
		{"manual-is-not-personal", "manual", now.Add(-time.Minute), now.Add(time.Minute), 2},
		{"expired", "second", now.Add(-time.Hour), now.Add(-time.Minute), 2},
		{"future", "second", now.Add(time.Minute), now.Add(time.Hour), 2},
		{"revoked", "unconsented", now.Add(-time.Minute), now.Add(time.Minute), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := autonomySourceRank(p, nodestore.Node{Origins: []nodestore.Origin{{SourceID: tc.source, ReceivedAt: tc.start, ExpiresAt: tc.end}}}, now); got != tc.want {
				t.Fatal(got, tc.want)
			}
		})
	}
}

func TestAutonomyOrderedSourceBucketsPreserveConsumedPrefixAndDeduplicateOrigins(t *testing.T) {
	a, ids, _ := autonomousIntegrationFixture(t)
	sourcePriorityImport(t, a, ids[0], "first", "")
	sourcePriorityImport(t, a, ids[1], "second", "")
	// The same configured node belongs to both sources, but remains one entry.
	sourcePriorityImport(t, a, ids[1], "first", "")
	p := a.autonomyPolicy()
	p.SourceIDs = []string{"manual", "first", "second"}
	p.PreferredSourceIDs = []string{"second", "first"}
	r := autonomy.Runtime{Search: &autonomy.Traversal{Ordered: []string{"consumed", ids[0], ids[1]}, Cursor: 1}}
	count, err := a.prioritizeAutonomySources(context.Background(), p, &r, time.Now())
	if err != nil || count != 2 || r.Search.Cursor != 1 || !slices.Equal(r.Search.Ordered, []string{"consumed", ids[1], ids[0]}) {
		t.Fatal("source rank rewrote prefix, ignored order or duplicated a node", err, r.Search)
	}
}

func TestAutonomyPrioritySourceRemovalWithdrawsPreferenceWithoutOtherChanges(t *testing.T) {
	a, ids, _ := autonomousIntegrationFixture(t)
	sourcePriorityImport(t, a, ids[1], "priority", "")
	sourcePriorityPolicy(t, a, 2)
	before := a.Store.Get()
	changed, paused, err := a.withdrawAutonomySource(context.Background(), "priority")
	p := a.autonomyPolicy()
	if err != nil || !changed || paused || len(p.PreferredSourceIDs) != 0 || !slices.Equal(p.SourceIDs, []string{"manual"}) || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("source withdrawal retained stale priority or changed live routes", err, p)
	}
	d10Reopen(t, a)
	if len(a.autonomyPolicy().PreferredSourceIDs) != 0 {
		t.Fatal("restart revived withdrawn source priority")
	}
}

func TestAutonomySourcePriorityDoesNotOverrideDomainBoundary(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	sourcePriorityImport(t, a, ids[1], "priority", "")
	for i := range a.Catalog.Services {
		if a.Catalog.Services[i].ID == "my-independent-site" {
			a.Catalog.Services[i].Domains = []string{"example.org"}
			a.Catalog.Services[i].CIDRs = nil
		}
	}
	service, _ := a.autonomyService("my-independent-site")
	a.autonomy.mu.Lock()
	s := a.autonomy.doc.Services[service.ID]
	s.Definition = autonomyDefinition(service)
	a.autonomy.doc.Services[service.ID] = s
	a.autonomy.mu.Unlock()
	var probes []string
	sourcePriorityProber(a, &probes)
	sourcePriorityPolicy(t, a, 2)
	a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		t.Fatal("source preference admitted a node for a domain service")
		return dataplane.NodeCheckResult{}, nil
	})
	a.autonomyRound(context.Background(), time.Now())
	if autonomyTestState(a).State != autonomyStateDomainRouteUnavailable || len(probes) != 0 || len(adapter.calls) != 0 {
		t.Fatal("domain boundary gained source-priority effects", autonomyTestState(a), probes, adapter.calls)
	}
}

func TestAutonomySourcePriorityDoesNotConsumePublicCachedPass(t *testing.T) {
	a, ids, _ := autonomousIntegrationFixture(t)
	sourcePriorityImport(t, a, ids[1], "priority", "")
	sourcePriorityPolicy(t, a, 1)
	now := time.Now()
	_, err := a.Nodes.RecordCheck(context.Background(), ids[0], nodestore.CheckRecord{ProbeID: "public-history", ServiceID: "my-independent-site", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + ids[0], TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Hour)}, now)
	if err != nil {
		t.Fatal(err)
	}
	var checked []string
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		return d10Result(req, "sing-box", true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	if !slices.Equal(checked, ids[1:]) || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+ids[1] {
		t.Fatal("public cached proof defeated selected source order", checked)
	}
}

func TestAutonomySourcePriorityAPIRequiresExistingConsentAndKeepsOrder(t *testing.T) {
	a, ids, _ := autonomousIntegrationFixture(t)
	sourcePriorityImport(t, a, ids[1], "priority", "")
	sourcePriorityPolicy(t, a, 2)
	p := a.autonomyPolicy()
	p.PreferredSourceIDs = []string{"priority", "manual"}
	w := httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY"}))
	if w.Code != 200 {
		t.Fatal("explicit ordered consented priorities refused", w.Code)
	}
	d10Reopen(t, a)
	p = a.autonomyPolicy()
	if !slices.Equal(p.PreferredSourceIDs, []string{"priority", "manual"}) {
		t.Fatal("priority order changed on reload")
	}
	view := a.autonomyView(time.Now())
	choices := view["source_choices"].([]map[string]any)
	if len(choices) != 2 || choices[0]["id"] != "manual" || choices[0]["name"] != "Добавленные вручную" || choices[1]["name"] != "Источник 2" || choices[1]["kind"] != "unknown" {
		t.Fatal("source choices disclose/infer unsupported provenance", choices)
	}
	p.PreferredSourceIDs = []string{"unconsented"}
	w = httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY"}))
	if w.Code != 400 || !slices.Equal(a.autonomyPolicy().PreferredSourceIDs, []string{"priority", "manual"}) {
		t.Fatal("priority expanded source consent", w.Code)
	}
}

func TestAutonomyPriorityCancellationDoesNotEnterStandardPhase(t *testing.T) {
	a, ids, _ := autonomousIntegrationFixture(t)
	sourcePriorityImport(t, a, ids[1], "priority", "")
	var probes []string
	sourcePriorityProber(a, &probes)
	sourcePriorityPolicy(t, a, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		cancel()
		return d10Result(req, "sing-box", true), ctx.Err()
	})
	a.autonomyRound(ctx, time.Now())
	r := autonomyTestState(a)
	if len(probes) != 0 || r.Search == nil || r.Search.Cursor != 0 || r.Search.StandardRoutesTried || len(r.Switches) != 0 {
		t.Fatal("canceled priority check entered standard phase", r, probes)
	}
}
