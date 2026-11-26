package app

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

// Seed observations at their original completion times. The round below runs
// the real admission, store, consent and checker path for the deciding check.
func TestFreeNodeRetirementWithoutServices(t *testing.T) {
	for _, scenario := range []string{"confirmed", "expired-old-success", "late-alias", "late-pin", "late-unrelated-config", "late-disable", "single", "two-strikes", "custom-two", "custom-four", "intervening-success", "transport", "wan", "other-network", "no-peer", "peer-stale", "new-receipt", "manual-origin", "alias", "pinned", "pending", "halted", "paused", "unowned-consent", "prior-success", "pending-traversal"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			a, _, _, checker, adapter, now := readinessFixture(t)
			feeds := openFreePoolFeeds(t, a)
			saved, err := feeds.Save(ctx, "", providerfeed.SaveRequest{Request: providerfeed.Request{PresetID: "igareck-black-vless"}, Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			origin := nodestore.Source{ID: saved.SourceID, Kind: "community"}
			p := &a.autonomy.doc.Policy
			p.SourceIDs = []string{saved.SourceID}
			p.PreferredRoutes = []string{"sing-box"}
			switch scenario {
			case "custom-two":
				p.PublicNodeFailureThreshold = 2
			case "custom-four":
				p.PublicNodeFailureThreshold = 4
			}
			a.autonomy.doc.Services = map[string]autonomy.Service{}
			a.reconciler.started = scenario != "pending"
			var ids, raw []string
			for i := 0; i < 2; i++ {
				uri := fmt.Sprintf("vless://123e4567-e89b-12d3-a456-42661417404%d@free%d.example:443?security=tls", i, i)
				raw = append(raw, uri)
				snap, err := a.Nodes.Import(ctx, origin, uri, now.Add(-time.Hour), 24*time.Hour, false)
				if err != nil {
					t.Fatal(err)
				}
				for _, n := range snap.Nodes {
					if n.Origins[0].SourceID == saved.SourceID && !slices.Contains(ids, n.ID) {
						ids = append(ids, n.ID)
						break
					}
				}
			}
			bad, peer := ids[0], ids[1]
			r := &a.nodeReadiness
			wan, _ := stableNodeProfile(ctx)
			r.network, r.engineSet, r.entries = wan, "sing-box", map[string]nodeReadinessEntry{}
			seed := func(id, key string, outcome nodeReadinessOutcome, at time.Time, network string) {
				item := nodeCheckItem{NodeID: id, Engine: "sing-box", ProbeID: key, NetworkProfile: network, TestLevel: "connectivity", CheckedAt: at, ExpiresAt: at.Add(dataplane.NodeConnectivityTTL), DirectControl: "measured", CleanupVerified: true}
				if outcome == nodeReadinessPass {
					item.Verdict, item.Stage, item.ConnectivityReady = "PASS", "connectivity", true
				} else {
					item.Verdict, item.Stage, item.ErrorCode = "ERROR", "egress", "node-egress-failed"
				}
				a.rememberNodeConnectivityLocked(item)
				r.observeLocked(id, item, at)
				e := r.entries[id]
				e.recordFreeProof(item, p.Revision, scenario != "unowned-consent", at)
				r.entries[id] = e
			}
			if scenario == "expired-old-success" {
				seed(bad, "old-success", nodeReadinessPass, now.Add(-55*time.Minute), wan)
			}
			if scenario == "prior-success" {
				seed(bad, "old-success", nodeReadinessPass, now.Add(-40*time.Minute), wan)
			}
			if scenario == "other-network" {
				seed(bad, "other", nodeReadinessEgress, now.Add(-49*time.Minute), "wan-other")
			}
			switch scenario {
			case "single":
			case "two-strikes", "custom-two":
				seed(bad, "strike-one", nodeReadinessEgress, now.Add(-13*time.Minute), wan)
			case "intervening-success":
				seed(bad, "older-strike", nodeReadinessEgress, now.Add(-38*time.Minute), wan)
				seed(bad, "middle-success", nodeReadinessPass, now.Add(-25*time.Minute), wan)
				seed(bad, "strike-one", nodeReadinessEgress, now.Add(-13*time.Minute), wan)
			default:
				seed(bad, "strike-one", nodeReadinessEgress, now.Add(-38*time.Minute), wan)
				seed(bad, "strike-two", nodeReadinessEgress, now.Add(-24*time.Minute), wan)
			}
			peerAt := now.Add(-time.Minute)
			if scenario == "peer-stale" {
				peerAt = now.Add(-6 * time.Minute)
			}
			if scenario != "no-peer" {
				seed(peer, "peer-pass", nodeReadinessPass, peerAt, wan)
			}
			r.cursor = peer
			checker.outcome = func(id string) string {
				if id == bad {
					switch scenario {
					case "transport", "wan":
						return scenario
					}
					return "egress"
				}
				return "pass"
			}
			switch scenario {
			case "new-receipt":
				_, err = a.Nodes.Import(ctx, origin, raw[0], now.Add(-time.Second), 24*time.Hour, false)
			case "manual-origin":
				_, err = a.Nodes.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, raw[0], now.Add(-time.Second), 24*time.Hour, false)
			case "alias":
				_, err = a.Nodes.SetAlias(ctx, bad, "My route", now)
			case "pending-traversal":
				a.autonomy.doc.Runtime["other"] = autonomy.Runtime{Search: &autonomy.Traversal{Ordered: []string{bad}}}
			case "pinned":
				err = a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "sing-box:" + bad})
			case "paused":
				r.pausedUntil = now.Add(time.Minute)
			case "halted":
				r.halted = true
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(scenario, "late-") {
				seed(bad, "strike-three", nodeReadinessEgress, now.Add(-10*time.Second), wan)
				original, err := a.Nodes.Snapshot(ctx, now)
				if err != nil {
					t.Fatal(err)
				}
				admitted, release, err := a.scopedRuntimeOperation(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
				reviewed := 0
				_, err = a.retireFreeNodes(admitted, *p, a.Store.Get(), original, wan, map[string]bool{"sing-box": true}, true, nil, func(c context.Context) error {
					reviewed++
					switch scenario {
					case "late-alias":
						_, e := a.Nodes.SetAlias(c, bad, "Keep", time.Now())
						return e
					case "late-pin":
						return a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "sing-box:" + bad})
					case "late-unrelated-config":
						return a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "direct"})
					case "late-disable":
						_, e := feeds.Save(c, saved.SourceID, providerfeed.SaveRequest{Enabled: false, Revision: saved.Revision})
						return e
					}
					return nil
				})
				if reviewed != 1 || (scenario != "late-pin" && err == nil) {
					t.Fatalf("missing final review/CAS fence: %d %v", reviewed, err)
				}
				after, e := a.Nodes.Snapshot(ctx, time.Now())
				if e != nil || !slices.ContainsFunc(after.Nodes, func(n nodestore.Node) bool { return n.ID == bad }) {
					t.Fatal("concurrent change lost", e)
				}
				return
			}
			before := a.Store.Get()
			a.nodeReadinessRound(ctx, now)
			if !reflect.DeepEqual(before, a.Store.Get()) || len(adapter.calls) != 0 {
				t.Fatal("readiness changed routing")
			}
			snap, err := a.Nodes.Snapshot(ctx, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			has := func(id string) bool {
				return slices.ContainsFunc(snap.Nodes, func(n nodestore.Node) bool { return n.ID == id })
			}
			removed := scenario == "confirmed" || scenario == "expired-old-success" || scenario == "custom-two"
			if !has(peer) || has(bad) == removed {
				t.Fatalf("bad=%v peer=%v calls=%d view=%+v", has(bad), has(peer), checker.count(), a.nodeReadinessSnapshot(now))
			}
			if scenario == "confirmed" {
				if r.retired[bad].until.IsZero() || r.entries[bad].Ready {
					t.Fatal("missing scoped retirement")
				}
				if _, err = a.Nodes.Import(ctx, origin, raw[0], time.Now(), 24*time.Hour, false); err != nil {
					t.Fatal(err)
				}
				calls := checker.count()
				a.nodeReadinessRound(ctx, now.Add(time.Minute))
				_, visible := r.entries[bad]
				if visible || checker.count() != calls {
					t.Fatal("same profile returned during the hold")
				}
				replacement := strings.Replace(raw[0], "174040", "174090", 1)
				changed, err := a.Nodes.Import(ctx, origin, replacement, time.Now(), 24*time.Hour, false)
				if err != nil {
					t.Fatal(err)
				}
				a.nodeReadinessRound(ctx, now.Add(2*time.Minute))
				if checker.count() != calls+1 || checker.last() == bad || checker.last() == peer || len(changed.Nodes) != len(snap.Nodes)+2 {
					t.Fatal("new material did not become available")
				}
			}
			if scenario == "single" && (r.entries[bad].Ready || r.entries[bad].Failures != 1 || !r.entries[bad].Next.After(now)) {
				t.Fatal("first failure must defer only", r.entries[bad])
			}
			if scenario == "two-strikes" || scenario == "custom-four" || scenario == "intervening-success" {
				want := 2
				if scenario == "custom-four" {
					want = 3
				}
				if checker.last() != bad || r.entries[bad].Failures != want {
					t.Fatalf("did not exercise the final failure: checks=%d failures=%d", checker.count(), r.entries[bad].Failures)
				}
			}
		})
	}
}

type freeFailoverChecker struct{ jobNodeChecker }

func (c freeFailoverChecker) CheckConnectivity(_ context.Context, r dataplane.NodeConnectivityRequest) (dataplane.NodeConnectivityResult, error) {
	return readyConnectivity(r), nil
}

// The original service proof must actually expire and the two failures
// require separate completions, ten seconds apart even with fake networking.
func TestFreeNodeRetirementAfterCommittedFailover(t *testing.T) {
	ctx := context.Background()
	a, _, adapter := autonomousIntegrationFixture(t)
	feeds := openFreePoolFeeds(t, a)
	src, err := feeds.Save(ctx, "", providerfeed.SaveRequest{Request: providerfeed.Request{PresetID: "igareck-black-vless"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i := 0; i < 2; i++ {
		link := fmt.Sprintf("vless://123e4567-e89b-12d3-a456-42661417408%d@new%d.example:443?security=tls", i, i)
		snap, err := a.Nodes.Import(ctx, nodestore.Source{ID: src.SourceID, Kind: "community"}, link, time.Now().Add(-time.Hour), 24*time.Hour, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range snap.Nodes {
			if n.Origins[0].SourceID == src.SourceID && !slices.Contains(ids, n.ID) {
				ids = append(ids, n.ID)
				break
			}
		}
	}
	slices.Sort(ids)
	a.nodeReviews.options = func() []routecatalog.Option {
		out := []routecatalog.Option{{ID: "direct", Installed: true, Configured: true, Selectable: true}, {ID: "sing-box", Installed: true, Configured: true, Selectable: true}}
		for _, id := range ids {
			out = append(out, routecatalog.Option{ID: "sing-box:" + id, Installed: true, Configured: true, Selectable: true, Services: []string{"my-independent-site"}})
		}
		return out
	}
	a.autonomy.doc.Policy.SourceIDs = []string{src.SourceID}
	a.autonomy.doc.Policy.PreferredRoutes = []string{"sing-box"}
	// This existing two-failure failover can retire only when explicitly
	// opted into the lower threshold. Default removal must keep the node.
	a.autonomy.doc.Policy.PublicNodeFailureThreshold = 2
	a.reconciler.started = true
	failed := ""
	var initialExpiry, firstFailure time.Time
	a.NodeChecker = freeFailoverChecker{jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		result := autofallbackResult(req, req.NodeID != failed)
		if req.NodeID == failed {
			result.Stage, result.TestLevel, result.ErrorCode = "egress", "protocol", "node-egress-failed"
			if firstFailure.IsZero() {
				firstFailure = result.FinishedAt
			}
		} else if failed == "" {
			result.ExpiresAt = result.FinishedAt.Add(2 * time.Second)
			initialExpiry = result.ExpiresAt
		}
		return result, nil
	})}
	a.autonomyRound(ctx, time.Now())
	if state := autonomyTestState(a); state.State != "applied" {
		t.Fatal("initial assignment", state.State, state.Message)
	}
	failed = ids[0]
	time.Sleep(time.Until(initialExpiry))
	autonomyTestDue(a, false)
	a.autonomyRound(ctx, time.Now())
	if state := autonomyTestState(a); state.Failures != 1 {
		t.Fatalf("first failure %v", state)
	}
	a.nodeReadinessRound(ctx, time.Now())
	snap, err := a.Nodes.Snapshot(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	has := func(id string) bool {
		return slices.ContainsFunc(snap.Nodes, func(n nodestore.Node) bool { return n.ID == id })
	}
	if !has(failed) {
		t.Fatal("active node removed")
	}
	time.Sleep(time.Until(firstFailure.Add(10 * time.Second)))
	autonomyTestDue(a, true)
	a.autonomyRound(ctx, time.Now())
	if state := autonomyTestState(a); state.State != "applied" || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+ids[1] || !slices.Contains(adapter.calls, "canary") || !slices.Contains(adapter.calls, "commit") {
		t.Fatalf("no committed replacement %v calls=%v", state.State, adapter.calls)
	}
	// Try the exact same successful transaction with one item of its
	// evidence withdrawn. None of these variants authorizes deletion.
	now := time.Now()
	snap, err = a.Nodes.Snapshot(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	wan, _ := stableNodeProfile(ctx)
	cfg := a.Store.Get()
	service := a.autonomy.doc.Services["my-independent-site"]
	p := a.nodeReadinessSourcePolicy(a.autonomy.doc.Policy, snap, true)
	observed := a.freeRotationSnapshot(snap)
	admitted, release, err := a.scopedRuntimeOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	replacements := a.freeServiceReplacements(admitted, p, []autonomy.Service{service}, cfg)
	release()
	for _, original := range snap.Nodes {
		if original.ID != failed {
			continue
		}
		for _, mode := range []string{"complete", "default-three", "other-service", "other-wan", "peer-later-failure", "peer-received-after-pass", "older-policy", "different-applied-generation", "missing-control", "changed-route"} {
			target := original
			policy := p
			target.Health.History = slices.Clone(target.Health.History)
			catalogue := snap
			catalogue.Nodes = slices.Clone(snap.Nodes)
			obs := observed
			obs.latest = maps.Clone(observed.latest)
			if obs.latest == nil {
				obs.latest = map[string]nodeCheckItem{}
			}
			obs.service = maps.Clone(observed.service)
			routes := maps.Clone(replacements)
			switch mode {
			case "default-three":
				policy.PublicNodeFailureThreshold = 0
			case "other-wan":
				target.Health.History[1].NetworkProfile = "wan-other"
			case "other-service":
				target.Health.History[1].ServiceID = "other"
			case "peer-later-failure":
				obs.latest[ids[1]] = nodeCheckItem{CheckedAt: now, Verdict: "ERROR"}
			case "peer-received-after-pass":
				for i := range catalogue.Nodes {
					if catalogue.Nodes[i].ID == ids[1] {
						catalogue.Nodes[i].Origins = slices.Clone(catalogue.Nodes[i].Origins)
						catalogue.Nodes[i].Origins[0].ReceivedAt = now
					}
				}
			case "older-policy":
				o := obs.service[failed]
				o.consent.revision--
				obs.service[failed] = o
			case "different-applied-generation":
				o := obs.service[failed]
				o.appliedFailures[len(o.appliedFailures)-1]++
				obs.service[failed] = o
			case "missing-control":
				delete(obs.service, ids[1])
			case "changed-route":
				delete(routes, service.ID)
			}
			allowed := freeNodeRemovalUntil(target, catalogue, policy, wan, now, obs, routes).After(now)
			if allowed != (mode == "complete") {
				t.Fatal("wrong exact decision", mode, allowed)
			}
		}
	}
	a.nodeReadinessRound(ctx, time.Now())
	snap, err = a.Nodes.Snapshot(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if has(failed) || !has(ids[1]) {
		t.Fatalf("released node retained=%v, replacement retained=%v", has(failed), has(ids[1]))
	}
}
