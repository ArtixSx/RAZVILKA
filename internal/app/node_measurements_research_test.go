package app

import (
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodequality"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"testing"
	"time"
)

func researchMeasuredNode(id, verdict, stage, code string, now time.Time) nodestore.Node {
	return nodestore.Node{ID: id, Health: nodestore.Health{History: []nodestore.CheckRecord{{ProbeID: "probe-" + id, ServiceID: "telegram", NetworkProfile: "wan-one", RoutePathID: "sing-box:" + id, TestLevel: "service", State: "available", Verdict: verdict, Stage: stage, ErrorCode: code, CheckedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), LatencyMS: 12345}}}}
}
func TestResearchNewRankingIgnoresLocalErrorAndLegacyDuration(t *testing.T) {
	now := time.Now()
	n := researchMeasuredNode("node-a", "ERROR", "cleanup", "node-cleanup-failed", now)
	s := nodeStability(n, "telegram", "wan-one", now)
	if s.failures != 0 || !s.attempted {
		t.Fatal(s)
	}
	n = researchMeasuredNode("node-a", "PASS", "service", "", now)
	if s = nodeStability(n, "telegram", "wan-one", now); s.passes != 1 || s.latencyMS != 0 {
		t.Fatal(s)
	}
}
func TestResearchNewRankingCountsRemoteRejection(t *testing.T) {
	now := time.Now()
	n := researchMeasuredNode("node-a", "BLOCKED", "service", "http-blocked", now)
	if s := nodeStability(n, "telegram", "wan-one", now); s.failures != 1 || s.passes != 0 {
		t.Fatal(s)
	}
}
func TestResearchNewRankingUsesExactFreshMeasurementAndKeepsHealthy(t *testing.T) {
	now := time.Now()
	a := researchMeasuredNode("node-a", "PASS", "service", "", now)
	b := researchMeasuredNode("node-b", "PASS", "service", "", now)
	snapshot := nodestore.Snapshot{Nodes: []nodestore.Node{a, b}}
	ms := int64(7)
	m := nodequality.Observation{Version: 1, NodeID: b.ID, ServiceID: "telegram", NetworkProfile: "wan-one", RoutePathID: "sing-box:" + b.ID, ProbeID: b.Health.History[0].ProbeID, CheckedAt: b.Health.History[0].CheckedAt, ExpiresAt: now.Add(time.Minute), ProxyResponseMS: &ms}
	got := rankAutonomyNodes(snapshot, []string{a.ID, b.ID}, "", "telegram", "wan-one", now, m)
	if got[0] != b.ID {
		t.Fatal(got)
	}
	got = rankAutonomyNodes(snapshot, []string{a.ID, b.ID}, a.ID, "telegram", "wan-one", now, m)
	if got[0] != a.ID {
		t.Fatal("healthy displaced", got)
	}
	m.ProbeID = "another-check"
	got = rankAutonomyNodes(snapshot, []string{b.ID, a.ID}, "", "telegram", "wan-one", now, m)
	if got[0] != a.ID {
		t.Fatal("unlinked metric", got)
	}
}
func TestResearchNewRankingDeduplicatesProbeRecords(t *testing.T) {
	now := time.Now()
	n := researchMeasuredNode("node-a", "PASS", "service", "", now)
	n.Health.History = append(n.Health.History, n.Health.History[0])
	if nodeStability(n, "telegram", "wan-one", now).passes != 1 {
		t.Fatal("double counted")
	}
}
func TestResearchRememberMeasurementUsesRequestNotTotal(t *testing.T) {
	now := time.Now()
	r := dataplane.NodeCheckResult{NodeID: "node-a", ServiceID: "telegram", NetworkProfile: "wan-one", RoutePathID: "sing-box:node-a", ProbeID: "probe-one", StartedAt: now.Add(-5 * time.Second), FinishedAt: now, ExpiresAt: now.Add(time.Minute), Available: true, Stages: []dataplane.NodeCheckStage{{ID: "tcp_connect", Status: "passed", Duration: 12}}, Evidence: evidence.ProbeEvidence{SchemaVersion: evidence.ProbeSchemaVersion, Outcome: evidence.OutcomeServiceAccepted, HTTPStatus: 200, Service: "telegram", NetworkProfile: "wan-one", ProbeID: "proof", RoutePathID: "sing-box:node-a", ExpectedRoutePathID: "sing-box:node-a", ObservedRoutePathID: "sing-box:node-a", Verdict: evidence.VerdictPass, StartedAt: now.Add(-100 * time.Millisecond), FinishedAt: now}}
	a := &App{}
	a.rememberNodeMeasurement(r)
	m := a.nodeMeasurements()
	if len(m) != 1 || *m[0].ProxyResponseMS != 100 || *m[0].TotalCheckMS != 5000 || *m[0].TCPConnectMS != 12 {
		t.Fatalf("%+v", m)
	}
}
func TestResearchRememberMeasurementRejectsUnconfirmedOrWrongTime(t *testing.T) {
	now := time.Now()
	r := dataplane.NodeCheckResult{NodeID: "node-a", ServiceID: "telegram", NetworkProfile: "wan-one", RoutePathID: "sing-box:node-a", ProbeID: "probe-one", StartedAt: now.Add(-time.Second), FinishedAt: now, ExpiresAt: now.Add(time.Minute), Available: false, Stages: []dataplane.NodeCheckStage{{ID: "tcp_connect", Status: "passed", Duration: 0}}}
	a := &App{}
	a.rememberNodeMeasurement(r)
	m := a.nodeMeasurements()
	if len(m) != 1 || m[0].ProxyResponseMS != nil || m[0].TCPConnectMS == nil || *m[0].TCPConnectMS != 0 {
		t.Fatal("bad evidence promotion")
	}
	r.FinishedAt = now.Add(time.Hour)
	a.rememberNodeMeasurement(r)
	if len(a.nodeMeasurements()) != 1 {
		t.Fatal("future data")
	}
}

func TestResearchRememberMeasurementRejectsMismatchedEvidence(t *testing.T) {
	now := time.Now()
	for _, mutate := range []func(*evidence.ProbeEvidence){
		func(p *evidence.ProbeEvidence) { p.NetworkProfile = "wan-other" },
		func(p *evidence.ProbeEvidence) { p.Service = "other" },
		func(p *evidence.ProbeEvidence) { p.ExpectedRoutePathID = "direct" },
		func(p *evidence.ProbeEvidence) { p.ObservedRoutePathID = "direct" },
		func(p *evidence.ProbeEvidence) { p.RouteProofError = "unproven" },
		func(p *evidence.ProbeEvidence) { p.NegativeControlMatched = true },
		func(p *evidence.ProbeEvidence) { p.HTTPStatus = 403 },
		func(p *evidence.ProbeEvidence) { p.Outcome = evidence.OutcomeUnknown },
	} {
		r := dataplane.NodeCheckResult{NodeID: "node-a", ServiceID: "telegram", NetworkProfile: "wan-one", RoutePathID: "sing-box:node-a", ProbeID: "probe-one", StartedAt: now.Add(-time.Second), FinishedAt: now, ExpiresAt: now.Add(time.Minute), Available: true,
			Evidence: evidence.ProbeEvidence{SchemaVersion: evidence.ProbeSchemaVersion, Outcome: evidence.OutcomeServiceAccepted, HTTPStatus: 200, Service: "telegram", NetworkProfile: "wan-one", ProbeID: "proof", RoutePathID: "sing-box:node-a", ExpectedRoutePathID: "sing-box:node-a", ObservedRoutePathID: "sing-box:node-a", Verdict: evidence.VerdictPass, StartedAt: now.Add(-100 * time.Millisecond), FinishedAt: now}}
		mutate(&r.Evidence)
		a := &App{}
		a.rememberNodeMeasurement(r)
		rows := a.nodeMeasurements()
		if len(rows) != 1 || rows[0].ProxyResponseMS != nil {
			t.Fatal("mismatched measurement accepted")
		}
	}
}
