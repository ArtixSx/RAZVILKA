package app

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
)

// Actual consent/config/NodeStore, latest-check TTL and managed source queue.
// Exact checker and OS adapter remain explicit models; no network I/O runs.
func refillFullReserveFixture(t *testing.T) (*App, []string, *nodeApplyAdapter) {
	t.Helper()
	a, ids, adapter := autonomyThreeReserveFixture(t)
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.ReserveTarget = 3
	r := a.autonomy.doc.Runtime["my-independent-site"]
	r.ReserveCheckedAt = time.Time{}
	a.autonomy.doc.Runtime["my-independent-site"] = r
	err := a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Now())
	r = autonomyTestState(a)
	if r.State != "healthy" || len(r.Reserves) != 3 {
		t.Fatal("did not prepare three genuinely checked reserves", r.State, len(r.Reserves))
	}
	adapter.calls = nil
	return a, ids, adapter
}

func refillManagedFeedFixture(t *testing.T, a *App) (*providerfeed.Manager, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "feeds")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	feeds, err := providerfeed.Open(a.Nodes, root)
	if err != nil {
		t.Fatal(err)
	}
	source, err := feeds.Save(context.Background(), "", providerfeed.SaveRequest{Request: providerfeed.Request{URL: "https://feed.example.test/approved", Limit: 32}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.SourceIDs = append(a.autonomy.doc.Policy.SourceIDs, source.SourceID)
	err = a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	feeds.StartManaged(ctx, func(c context.Context) (func(), error) { <-c.Done(); return nil, c.Err() })
	t.Cleanup(func() {
		cancel()
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := feeds.Wait(ctx); err != nil {
			t.Error(err)
		}
		if err := feeds.Close(); err != nil {
			t.Error(err)
		}
	})
	return feeds, source.SourceID
}

func refillQueuedJob(t *testing.T, feeds *providerfeed.Manager, sourceID string) string {
	t.Helper()
	for _, state := range feeds.List() {
		if state.SourceID == sourceID {
			return state.JobID
		}
	}
	t.Fatal("approved source disappeared")
	return ""
}

func TestAutonomyRefillStaleFullReservesAfterConfirmedCurrentFailure(t *testing.T) {
	a, ids, adapter := refillFullReserveFixture(t)
	feeds, sourceID := refillManagedFeedFixture(t, a)
	for _, id := range ids[1:] {
		if _, err := a.Nodes.SetDisabled(context.Background(), id, true, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	var checked []string
	a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, request.NodeID)
		return d10Result(request, "sing-box", false), nil
	})
	// Keep the passive worker detached until the actual two-check quorum.
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Now())
	if state := autonomyTestState(a); state.Failures != 1 {
		t.Fatal("first actual current failure not recorded")
	}
	a.NodeFeeds = feeds
	before := a.Store.Get()
	autonomyTestDue(a, true)
	a.autonomyRound(context.Background(), time.Now())
	r := autonomyTestState(a)
	if r.State != "searching" || r.Search == nil || !r.Search.Exhausted || len(r.Reserves) != 3 || !reflect.DeepEqual(checked, []string{ids[0], ids[0]}) {
		t.Fatal("did not reach the stale-full first-usable counterexample", r.State, r.Search, len(r.Reserves), checked)
	}
	a.autonomy.mu.Lock()
	decision := a.autonomy.refillState
	p, s := a.autonomy.doc.Policy, a.autonomy.doc.Services["my-independent-site"]
	a.autonomy.mu.Unlock()
	jobID := refillQueuedJob(t, feeds, sourceID)
	if decision.State != "queued" || decision.SourceID != sourceID || jobID == "" {
		t.Fatal("stale full list suppressed real demand refill", decision)
	}
	if !reflect.DeepEqual(before, a.Store.Get()) || len(adapter.calls) != 0 {
		t.Fatal("passive refill changed route/config or invoked Apply")
	}
	snapshot, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	profile, err := a.freshNetworkProfile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count, err := a.freshAutonomyReserveCount(context.Background(), snapshot, p, s, r, "sing-box", profile, time.Now()); err != nil || count != 0 {
		t.Fatal("latest FAIL resurrected old PASS", count, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	a.autonomyRefill(ctx, p, s, r)
	if next := refillQueuedJob(t, feeds, sourceID); next != jobID {
		t.Fatal("same demand created another job")
	}
	after, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil || !reflect.DeepEqual(snapshot, after) || !reflect.DeepEqual(r, autonomyTestState(a)) {
		t.Fatal("refill renewed node proof/origin or mutated cached runtime", err)
	}
}

func TestAutonomyRefillCountsOnlyFreshPermittedExactDistinctReserves(t *testing.T) {
	for _, changed := range []string{"fresh", "proof-expired", "disabled", "origin-expired", "disallowed-origin", "foreign-engine", "foreign-network", "foreign-service", "candidate-cooldown", "missing", "duplicate", "same-server", "store-read-error"} {
		t.Run(changed, func(t *testing.T) {
			a, ids, _ := refillFullReserveFixture(t)
			p := a.autonomyPolicy()
			a.autonomy.mu.Lock()
			s := a.autonomy.doc.Services["my-independent-site"]
			a.autonomy.mu.Unlock()
			r := autonomyTestState(a)
			profile, err := a.freshNetworkProfile(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			engine, want := "sing-box", 3
			now := time.Now().UTC()
			switch changed {
			case "proof-expired":
				_, err = a.Nodes.RecordCheck(context.Background(), ids[1], nodestore.CheckRecord{ProbeID: "refill-expiring", ServiceID: s.ID, NetworkProfile: profile, RoutePathID: "sing-box:" + ids[1], TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: now, ExpiresAt: now.Add(time.Nanosecond)}, now)
				want = 2
			case "disabled":
				_, err = a.Nodes.SetDisabled(context.Background(), ids[1], true, now)
				want = 2
			case "origin-expired":
				// Re-import the same actual three fixture profiles with a newer
				// nanosecond origin TTL, through the real atomic store API.
				for _, raw := range []string{"vless://123e4567-e89b-12d3-a456-426614174000@private.example:443?security=tls", "vless://123e4567-e89b-12d3-a456-426614174001@reserve.example:443?security=tls", "vless://123e4567-e89b-12d3-a456-426614174002@third.example:443?security=tls"} {
					_, err = a.Nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, raw, now, time.Nanosecond, false)
					if err != nil {
						break
					}
				}
				want = 0
			case "disallowed-origin":
				p.SourceIDs = []string{"another-approved-source"}
				want = 0
			case "foreign-engine":
				engine = "xray"
				want = 0
			case "foreign-network":
				profile = "wan-ffffffffffff"
				want = 0
			case "foreign-service":
				s.ID = "other-service"
				want = 0
			case "candidate-cooldown":
				r.RecordCandidateFailure(autonomy.CandidateFailure{NodeID: ids[1], Network: profile, Definition: s.Definition, Scope: autonomy.ScopeFingerprint(s.Sources), Code: "http-403", ObservedAt: now})
				want = 2
			case "missing":
				r.Reserves = []string{"node-00000000000000000000000000000000"}
				want = 0
			case "duplicate":
				r.Reserves = []string{ids[0], ids[0], ids[0]}
				want = 1
			case "same-server":
				imported, e := a.Nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174008@same-server.example:443?security=tls\nvless://123e4567-e89b-12d3-a456-426614174009@same-server.example:443?security=tls", now, time.Hour, false)
				if e != nil {
					t.Fatal(e)
				}
				r.Reserves = []string{ids[0]}
				for _, node := range imported.Nodes {
					if slices.Contains(ids, node.ID) {
						continue
					}
					_, err = a.Nodes.RecordCheck(context.Background(), node.ID, nodestore.CheckRecord{ProbeID: "refill-same-server-" + node.ID, ServiceID: s.ID, NetworkProfile: profile, RoutePathID: "sing-box:" + node.ID, TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: now, ExpiresAt: now.Add(time.Minute)}, now)
					if err != nil {
						break
					}
					r.Reserves = append(r.Reserves, node.ID)
				}
				if len(r.Reserves) != 3 {
					t.Fatal("did not import two credentials for one actual configured server")
				}
				want = 2
			}
			if err != nil {
				t.Fatal("real store mutation failed", err)
			}
			snapshot, err := a.Nodes.Snapshot(context.Background(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if changed == "store-read-error" {
				if err := a.Nodes.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := a.freshAutonomyReserveCount(context.Background(), snapshot, p, s, r, engine, profile, time.Now()); err == nil {
					t.Fatal("unreadable actual store became a valid empty pool")
				}
				return
			}
			if count, err := a.freshAutonomyReserveCount(context.Background(), snapshot, p, s, r, engine, profile, time.Now()); err != nil || count != want {
				t.Fatal("wrong genuine reserve count", count, want, err)
			}
		})
	}
}

func TestAutonomyRefillFreshFullPoolAndResourceOrReadRefusalsDoNotQueue(t *testing.T) {
	for _, guard := range []string{"fresh-full", "resource-excluded", "policy-revoked", "cancelled", "store-closed", "safe-mode", "stopped", "manual", "unfinished-search"} {
		t.Run(guard, func(t *testing.T) {
			a, ids, _ := refillFullReserveFixture(t)
			feeds, sourceID := refillManagedFeedFixture(t, a)
			a.NodeFeeds = feeds
			p := a.autonomyPolicy()
			a.autonomy.mu.Lock()
			s := a.autonomy.doc.Services["my-independent-site"]
			a.autonomy.mu.Unlock()
			r := autonomyTestState(a)
			if guard != "fresh-full" {
				r.Reserves = nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ctx, release, err := a.privateExclusiveOperation(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			switch guard {
			case "resource-excluded":
				manual := []config.ResourceMatch{{Kind: "service", Value: s.ID}}
				_, err = a.Store.UpdateResourceExclusions(ctx, a.Store.Get(), &manual, nil)
			case "policy-revoked":
				p.Revision++
			case "cancelled":
				cancel()
			case "store-closed":
				err = a.Nodes.Close()
			case "safe-mode":
				err = a.Store.SetSafeMode(true)
			case "stopped":
				_, err = a.Store.CommitServiceRuntime(true, map[string]string{s.ID: s.ExpectedRoute}, a.Store.Get().Revision)
			case "manual":
				mode := "manual"
				err = a.Store.UpdateServiceControl(&mode, nil, a.Store.Get().Revision)
			case "unfinished-search":
				profile, e := a.freshNetworkProfile(ctx)
				if e != nil {
					t.Fatal(e)
				}
				r.Search = &autonomy.Traversal{Version: autonomyTraversalVersion(p, s, "sing-box", profile), Ordered: slices.Clone(ids), Exhausted: false}
			}
			if err != nil {
				t.Fatal(err)
			}
			a.autonomyRefill(ctx, p, s, r)
			if refillQueuedJob(t, feeds, sourceID) != "" {
				t.Fatal("fresh full pool or guard refusal queued refill")
			}
		})
	}
}
