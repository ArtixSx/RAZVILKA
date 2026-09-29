package app

import (
	"fmt"
	"slices"
	"testing"
	"time"

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
