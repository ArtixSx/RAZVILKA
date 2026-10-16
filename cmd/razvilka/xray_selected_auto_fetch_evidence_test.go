package main

import (
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodequality"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// Read-only selection from actual producer histories. The portable tests below
// model those histories only; they do not issue checks or native authority.
func xrayAutoFailureHistory(nodes []nodestore.Node, ids [2]string, service, network string, fault time.Time, gap time.Duration, now time.Time) (first, second, failureB nodestore.CheckRecord) {
	for _, node := range nodes {
		if node.ID == ids[0] {
			first, second = xrayAutoFailurePair(node, service, network, fault, gap, now)
		}
	}
	if second.CheckedAt.IsZero() {
		return
	}
	// A healthy-current round may already have checked B before A's second
	// failure. Recompute from this snapshot after establishing the A quorum;
	// neither node ordering nor a prior poll's earliest B can hide a later check.
	for _, node := range nodes {
		if node.ID == ids[1] {
			for _, record := range node.Health.History {
				if record.RoutePathID == "xray:"+node.ID && xrayAutoTerminalFailure(record, service, network, second.CheckedAt, now) && (failureB.CheckedAt.IsZero() || record.CheckedAt.Before(failureB.CheckedAt)) {
					failureB = record
				}
			}
		}
	}
	return
}

func xrayAutoTerminalFailure(record nodestore.CheckRecord, service, network string, after, now time.Time) bool {
	if record.ServiceID != service || record.NetworkProfile != network || !strings.HasPrefix(record.RoutePathID, "xray:node-") || record.CheckedAt.Before(after) || record.CheckedAt.After(now) || !record.ExpiresAt.After(now) || record.DirectLeak {
		return false
	}
	return nodequality.ServiceFailure(record.Verdict, record.TestLevel, record.Stage, record.ErrorCode, record.DirectLeak) || record.State == "unavailable" && record.Verdict == "ERROR" && record.HTTPStatus == 0 && record.EgressIP == "" && (record.TestLevel == "transport" && record.Stage == "transport" && record.ErrorCode == "node-transport-failed" || record.TestLevel == "protocol" && record.Stage == "egress" && record.ErrorCode == "node-egress-failed")
}

func xrayAutoFailurePair(node nodestore.Node, service, network string, after time.Time, gap time.Duration, now time.Time) (nodestore.CheckRecord, nodestore.CheckRecord) {
	var first, second nodestore.CheckRecord
	// Histories are newest first. An intervening ambiguous/PASS observation
	// breaks the quorum; runtime's actual Observe bookend is checked separately.
	for i := len(node.Health.History) - 1; i >= 0; i-- {
		r := node.Health.History[i]
		if r.CheckedAt.Before(after) {
			continue
		}
		if r.RoutePathID != "xray:"+node.ID || !xrayAutoTerminalFailure(r, service, network, after, now) {
			first, second = nodestore.CheckRecord{}, nodestore.CheckRecord{}
			continue
		}
		if first.CheckedAt.IsZero() {
			first = r
		} else if r.CheckedAt.Sub(first.CheckedAt) >= gap {
			second = r
			break
		}
	}
	return first, second
}

func xrayAutoHistoryModel() ([]nodestore.Node, time.Time, time.Time) {
	fault := time.Date(2026, 10, 16, 4, 0, 0, 0, time.UTC)
	now := fault.Add(2 * time.Minute)
	record := func(id string, offset time.Duration) nodestore.CheckRecord {
		return nodestore.CheckRecord{ProbeID: id, ServiceID: "qa", NetworkProfile: "original-network", RoutePathID: "xray:node-a",
			TestLevel: "transport", Stage: "transport", State: "unavailable", Verdict: "ERROR", ErrorCode: "node-transport-failed",
			CheckedAt: fault.Add(offset), ExpiresAt: now.Add(time.Hour)}
	}
	a := nodestore.Node{ID: "node-a", Health: nodestore.Health{History: []nodestore.CheckRecord{record("a2", 40*time.Second), record("a1", 10*time.Second)}}}
	b := nodestore.Node{ID: "node-b", Health: nodestore.Health{History: []nodestore.CheckRecord{record("b-after", 50*time.Second), record("b-before", 20*time.Second)}}}
	for i := range b.Health.History {
		b.Health.History[i].RoutePathID = "xray:node-b"
	}
	return []nodestore.Node{a, b}, fault, now
}

func TestXrayAutoFetchFailureHistoryUsesBOnlyAfterConfirmedAQuorum(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		nodes, fault, now := xrayAutoHistoryModel()
		if reverse {
			nodes[0], nodes[1] = nodes[1], nodes[0]
		}
		first, second, b := xrayAutoFailureHistory(nodes, [2]string{"node-a", "node-b"}, "qa", "original-network", fault, 20*time.Second, now)
		if first.ProbeID != "a1" || second.ProbeID != "a2" || b.ProbeID != "b-after" || b.CheckedAt.Before(second.CheckedAt) {
			t.Fatal("an earlier B observation hid the new real post-quorum failure", first.ProbeID, second.ProbeID, b.ProbeID)
		}
	}
}

func TestXrayAutoFetchFailureHistoryNeverUsesOldOrAmbiguousB(t *testing.T) {
	for _, kind := range []string{"only-before", "no-a2", "429", "ambiguous", "expired", "future", "foreign-route", "foreign-service", "foreign-network", "leak"} {
		t.Run(kind, func(t *testing.T) {
			nodes, fault, now := xrayAutoHistoryModel()
			r := &nodes[1].Health.History[0]
			switch kind {
			case "only-before":
				nodes[1].Health.History = nodes[1].Health.History[1:]
			case "no-a2":
				nodes[0].Health.History = nodes[0].Health.History[1:]
			case "429":
				r.TestLevel, r.Stage, r.Verdict, r.State, r.HTTPStatus, r.ErrorCode = "service", "service", "PARTIAL", "partial", 429, "http-429"
			case "ambiguous":
				r.TestLevel, r.Stage, r.Verdict, r.State, r.ErrorCode = "service", "service", "INCONCLUSIVE", "unknown", "timeout"
			case "expired":
				r.ExpiresAt = now
			case "future":
				r.CheckedAt = now.Add(time.Second)
			case "foreign-route":
				r.RoutePathID = "xray:node-a"
			case "foreign-service":
				r.ServiceID = "other"
			case "foreign-network":
				r.NetworkProfile = "other"
			case "leak":
				r.DirectLeak = true
			}
			_, _, b := xrayAutoFailureHistory(nodes, [2]string{"node-a", "node-b"}, "qa", "original-network", fault, 20*time.Second, now)
			if !b.CheckedAt.IsZero() {
				t.Fatal("missing post-quorum exact terminal B was accepted", b.ProbeID)
			}
		})
	}
}

func TestXrayAutoFetchFailureHistoryKeepsTerminalKindsAndBreaksAmbiguousAQuorum(t *testing.T) {
	for _, kind := range []string{"transport", "protocol", "service"} {
		t.Run(kind, func(t *testing.T) {
			nodes, fault, now := xrayAutoHistoryModel()
			r := &nodes[1].Health.History[0]
			if kind == "protocol" {
				r.TestLevel, r.Stage, r.ErrorCode = "protocol", "egress", "node-egress-failed"
			} else if kind == "service" {
				r.TestLevel, r.Stage, r.Verdict, r.ErrorCode, r.HTTPStatus = "service", "service", "BLOCKED", "http-403", 403
			}
			_, _, b := xrayAutoFailureHistory(nodes, [2]string{"node-a", "node-b"}, "qa", "original-network", fault, 20*time.Second, now)
			if b.ProbeID != "b-after" {
				t.Fatal("fresh definite B failure was lost", b.ProbeID)
			}
		})
	}
	for _, verdict := range []string{"PASS", "INCONCLUSIVE", "PARTIAL"} {
		t.Run("intervening-a-"+verdict, func(t *testing.T) {
			nodes, fault, now := xrayAutoHistoryModel()
			middle := nodes[0].Health.History[0]
			middle.CheckedAt = fault.Add(25 * time.Second)
			middle.Verdict, middle.TestLevel, middle.Stage, middle.ErrorCode = verdict, "service", "service", ""
			if verdict == "PARTIAL" {
				middle.HTTPStatus, middle.ErrorCode = 429, "http-429"
			}
			nodes[0].Health.History = []nodestore.CheckRecord{nodes[0].Health.History[0], middle, nodes[0].Health.History[1]}
			_, second, b := xrayAutoFailureHistory(nodes, [2]string{"node-a", "node-b"}, "qa", "original-network", fault, 20*time.Second, now)
			if !second.CheckedAt.IsZero() || !b.CheckedAt.IsZero() {
				t.Fatal("ambiguous/PASS A contributed to the quorum")
			}
		})
	}
}
