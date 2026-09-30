package app

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func rankedNode(id string, now time.Time, checks ...string) nodestore.Node {
	n := nodestore.Node{ID: id}
	for i, c := range checks {
		record := nodestore.CheckRecord{ProbeID: fmt.Sprintf("p%d", i), ServiceID: "telegram", NetworkProfile: "wan-1", RoutePathID: "sing-box:" + id,
			TestLevel: "service", CheckedAt: now.Add(-time.Duration(i+1) * time.Minute)}
		switch c {
		case "fast":
			record.Verdict, record.LatencyMS = "PASS", 80
		case "slow":
			record.Verdict, record.LatencyMS = "PASS", 900
		case "fail":
			record.Verdict = "ERROR"
		case "other-service":
			record.Verdict, record.ServiceID = "PASS", "whatsapp"
		case "other-network":
			record.Verdict, record.NetworkProfile = "PASS", "wan-2"
		case "old":
			record.Verdict, record.CheckedAt = "PASS", now.Add(-48*time.Hour)
		case "unsure":
			record.Verdict = "INCONCLUSIVE"
		}
		n.Health.History = append(n.Health.History, record)
	}
	return n
}

func TestRankAutonomyNodesPrefersStableThenFast(t *testing.T) {
	now := time.Now()
	snapshot := nodestore.Snapshot{Nodes: []nodestore.Node{
		rankedNode("node-a", now, "fast", "fail", "fail"),                            // 1 of 3
		rankedNode("node-b", now, "slow", "slow", "slow"),                            // 3 of 3, slow
		rankedNode("node-c", now, "fast", "fast", "fast"),                            // 3 of 3, fast
		rankedNode("node-d", now, "other-service", "other-network", "old", "unsure"), // no record
		rankedNode("node-e", now, "fast", "fast", "fast", "fast", "fail"),            // 4 of 5
	}}
	ids := []string{"node-a", "node-b", "node-c", "node-d", "node-e"}
	got := rankAutonomyNodes(snapshot, ids, "", "telegram", "wan-1", now)
	want := []string{"node-c", "node-b", "node-e", "node-d", "node-a"}
	if !slices.Equal(got, want) {
		t.Fatalf("ranking %v, want %v", got, want)
	}
	// A working current node is never displaced by a more stable reserve.
	got = rankAutonomyNodes(snapshot, ids, "node-a", "telegram", "wan-1", now)
	if got[0] != "node-a" || got[1] != "node-c" {
		t.Fatalf("current node displaced: %v", got)
	}
}

func TestUncheckedAutonomyCandidatesCountsOnlyPermittedUnchecked(t *testing.T) {
	now := time.Now()
	p := autonomy.Default()
	p.SourceIDs = []string{"feed"}
	origin := []nodestore.Origin{{SourceID: "feed", ReceivedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}}
	fresh := func(id string) nodestore.Node {
		return nodestore.Node{ID: id, Protocol: "VLESS", Origins: origin}
	}
	checked := rankedNode("node-c", now, "fail")
	checked.Protocol, checked.Origins = "VLESS", origin
	otherService := rankedNode("node-o", now, "other-service")
	otherService.Protocol, otherService.Origins = "VLESS", origin
	expired := fresh("node-x")
	expired.Origins = []nodestore.Origin{{SourceID: "feed", ReceivedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-24 * time.Hour)}}
	foreign := fresh("node-f")
	foreign.Origins = []nodestore.Origin{{SourceID: "other", ReceivedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}}
	snapshot := nodestore.Snapshot{Nodes: []nodestore.Node{fresh("node-1"), fresh("node-2"), checked, otherService, expired, foreign}}
	if got := uncheckedAutonomyCandidates(snapshot, p, "telegram", "wan-1", now); got != 3 {
		t.Fatalf("unchecked %d, want 3", got)
	}
}

// Candidates of a source that served the service come first, unchecked
// before already failed; a large weak source cannot take every round.
func TestOrderAutonomyCandidatesPrefersProvenSources(t *testing.T) {
	now := time.Now()
	origin := func(n nodestore.Node, source string) nodestore.Node {
		n.Origins = []nodestore.Origin{{SourceID: source, ReceivedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}}
		return n
	}
	snapshot := nodestore.Snapshot{Nodes: []nodestore.Node{
		origin(rankedNode("node-a1", now, "fast"), "good"),
		origin(rankedNode("node-a2", now), "good"),
		origin(rankedNode("node-a3", now, "fail"), "good"),
		origin(rankedNode("node-b1", now, "fail", "fail"), "weak"),
		origin(rankedNode("node-b2", now), "weak"),
		origin(rankedNode("node-b3", now), "weak"),
	}}
	got := orderAutonomyCandidates(snapshot, []string{"node-b3", "node-b2", "node-b1", "node-a3", "node-a2", "node-a1"}, "telegram", "wan-1", now)
	want := []string{"node-a2", "node-a1", "node-a3", "node-b2", "node-b3", "node-b1"}
	if !slices.Equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}
