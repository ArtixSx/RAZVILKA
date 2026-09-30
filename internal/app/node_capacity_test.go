package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func feedURIs(host string, count int) string {
	lines := make([]string, count)
	for i := range lines {
		lines[i] = fmt.Sprintf("vless://123e4567-e89b-12d3-a456-%012d@%s-%d.example:443?security=tls", i, host, i)
	}
	return strings.Join(lines, "\n")
}

// A profile carries at most 128 nodes; import larger catalogues in windows.
func importFeedWindows(t *testing.T, nodes *nodestore.Store, source nodestore.Source, host string, count int, at time.Time) []string {
	t.Helper()
	ids := []string{}
	for start := 0; start < count; start += 100 {
		size := min(100, count-start)
		snapshot, err := nodes.Import(context.Background(), source, feedURIs(fmt.Sprintf("%s%d", host, start), size), at, 24*time.Hour, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range snapshot.Nodes {
			if !slices.Contains(ids, n.ID) && len(n.Origins) > 0 && n.Origins[len(n.Origins)-1].SourceID == source.ID && n.Origins[len(n.Origins)-1].ReceivedAt.Equal(at.UTC()) {
				ids = append(ids, n.ID)
			}
		}
	}
	if len(ids) != count {
		t.Fatalf("imported %d of %d", len(ids), count)
	}
	return ids
}

func nodeCapacityFixture(t *testing.T) (*App, *nodestore.Store, time.Time) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nodes"), 0o700); err != nil {
		t.Fatal(err)
	}
	nodes, err := nodestore.Open(filepath.Join(root, "nodes"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nodes.Close() })
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &App{Nodes: nodes, Store: store}, nodes, time.Now().UTC()
}

func TestPruneExpiredFeedNodesFreesTheCatalogue(t *testing.T) {
	a, nodes, now := nodeCapacityFixture(t)
	ctx := context.Background()
	past := now.Add(-72 * time.Hour)
	ids := importFeedWindows(t, nodes, nodestore.Source{ID: "feed-old", Kind: "community"}, "old", 400, past)
	// The same server also imported by hand keeps the owner's origin.
	if _, err := nodes.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, feedURIs("old0", 1), past, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	if _, err := nodes.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174999@own.example:443?security=tls", past, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	fresh, err := nodes.Import(ctx, nodestore.Source{ID: "feed-new", Kind: "subscription"}, feedURIs("new", 2), now.Add(-time.Minute), 24*time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = nodes.SetDisabled(ctx, ids[1], true, now); err != nil {
		t.Fatal(err)
	}
	if _, err = nodes.CreateGroup(ctx, "Reserve", "fallback", []string{ids[2]}, "", time.Minute, now); err != nil {
		t.Fatal(err)
	}
	if err = a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "sing-box:" + ids[3]}); err != nil {
		t.Fatal(err)
	}
	removed, err := a.pruneExpiredFeedNodes(ctx, now)
	if err != nil || removed != 396 {
		t.Fatalf("removed %d: %v", removed, err)
	}
	after, err := nodes.Snapshot(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	kept := map[string]bool{}
	for _, n := range after.Nodes {
		kept[n.ID] = true
	}
	for i, why := range []string{"manual origin", "disabled", "group member", "selected route"} {
		if !kept[ids[i]] {
			t.Fatalf("%s node was removed", why)
		}
	}
	for _, n := range fresh.Nodes {
		if n.Origins[0].SourceID == "feed-new" && !kept[n.ID] {
			t.Fatal("fresh feed node was removed")
		}
	}
	// 4 protected old nodes, the owner's own node and 2 fresh ones.
	if len(after.Nodes) != 7 {
		t.Fatalf("kept %d nodes", len(after.Nodes))
	}
	// A feed can import a new window again.
	if _, err = nodes.Import(ctx, nodestore.Source{ID: "feed-old", Kind: "community"}, feedURIs("next", 32), now, 24*time.Hour, false); err != nil {
		t.Fatal("import after pruning:", err)
	}
}

func TestPruneExpiredFeedNodesWaitsForPressureGraceAndInterval(t *testing.T) {
	a, nodes, now := nodeCapacityFixture(t)
	ctx := context.Background()
	importFeedWindows(t, nodes, nodestore.Source{ID: "feed-old", Kind: "community"}, "old", 100, now.Add(-72*time.Hour))
	if removed, err := a.pruneExpiredFeedNodes(ctx, now); err != nil || removed != 0 {
		t.Fatalf("pruned below pressure: %d %v", removed, err)
	}
	// Expired less than the grace period ago: a slow feed may still renew it.
	importFeedWindows(t, nodes, nodestore.Source{ID: "feed-recent", Kind: "community"}, "recent", 300, now.Add(-24*time.Hour-time.Minute))
	if removed, err := a.pruneExpiredFeedNodes(ctx, now); err != nil || removed != 0 {
		t.Fatalf("interval not respected: %d %v", removed, err)
	}
	later := now.Add(feedPruneInterval)
	removed, err := a.pruneExpiredFeedNodes(ctx, later)
	if err != nil || removed != 100 {
		t.Fatalf("grace not respected: %d %v", removed, err)
	}
}

func recordNodeCheck(t *testing.T, nodes *nodestore.Store, id, verdict, code string, at time.Time) {
	t.Helper()
	record := nodestore.CheckRecord{ProbeID: fmt.Sprintf("probe-%d", at.UnixNano()), ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id,
		TestLevel: "transport", Verdict: verdict, State: "unavailable", Stage: "transport", ErrorCode: code, CheckedAt: at, ExpiresAt: at.Add(time.Hour)}
	if verdict == "PASS" {
		record.TestLevel, record.State, record.Stage = "service", "available", "service"
	}
	if _, err := nodes.RecordCheck(context.Background(), id, record, at); err != nil {
		t.Fatal(err)
	}
}

// Fresh candidates that could not connect or reach the internet are removed
// under pressure; a node with a success on record or a service-level failure
// is kept.
func TestPruneFailedFeedCandidatesUnderPressure(t *testing.T) {
	a, nodes, now := nodeCapacityFixture(t)
	ctx := context.Background()
	ids := importFeedWindows(t, nodes, nodestore.Source{ID: "feed-new", Kind: "community"}, "new", 400, now.Add(-time.Hour))
	for i, id := range ids[:10] {
		recordNodeCheck(t, nodes, id, "ERROR", []string{"node-transport-failed", "node-egress-failed"}[i%2], now.Add(-30*time.Minute))
	}
	recordNodeCheck(t, nodes, ids[10], "PASS", "", now.Add(-40*time.Minute))
	recordNodeCheck(t, nodes, ids[10], "ERROR", "node-transport-failed", now.Add(-20*time.Minute))
	recordNodeCheck(t, nodes, ids[11], "ERROR", "node-service-probe-failed", now.Add(-20*time.Minute))
	removed, err := a.pruneExpiredFeedNodes(ctx, now)
	if err != nil || removed != 10 {
		t.Fatalf("removed %d: %v", removed, err)
	}
	after, err := nodes.Snapshot(ctx, now)
	if err != nil || len(after.Nodes) != 390 {
		t.Fatalf("kept %d: %v", len(after.Nodes), err)
	}
}
