package dataplane

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNodePlanDigestAndCanaryCarryNetworkEpoch(t *testing.T) {
	input := Input{NetworkProfileID: "wan-111111111111", Routes: []Route{{ServiceID: "test", Selected: "sing-box:group-test", Resolved: "sing-box:node-test"}}}
	first, err := BuildAt(input, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	input.NetworkProfileID = "wan-222222222222"
	second, err := BuildAt(input, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest == second.Digest || first.PlanID == second.PlanID {
		t.Fatal("network transition reused a reviewed plan")
	}
	ir := first.RoutePlanFor("sing-box")
	if !ir.RequiresNetworkProof() || ir.NetworkProfileID != first.NetworkProfileID {
		t.Fatal("candidate lost the reviewed network epoch")
	}
	if first.RoutePlanFor("usque").RequiresNetworkProof() {
		t.Fatal("unrelated adapter inherited node authority")
	}
}

func TestNodePlanWithoutKnownNetworkIsBlockedButHistoryReadable(t *testing.T) {
	for _, profile := range []string{"", "network-unknown", "wan-invalid"} {
		p, err := Build(Input{NetworkProfileID: profile, Routes: []Route{{Resolved: "sing-box:node-test"}}})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, blocker := range p.Blockers {
			found = found || blocker.Code == "NETWORK_PROOF_UNAVAILABLE"
		}
		if p.Ready || !found {
			t.Fatalf("missing network blocker for %q", profile)
		}
	}
	var legacy Plan
	if err := json.Unmarshal([]byte(`{"schema_version":1,"state":"committed","routes":[{"resolved_route":"sing-box:node-test"}]}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if !legacy.RequiresNetworkProof() || legacy.NetworkProfileID != "" {
		t.Fatal("legacy history gained authority")
	}
	direct, err := Build(Input{Routes: []Route{{Resolved: "direct"}}})
	if err != nil || !direct.Ready || direct.RequiresNetworkProof() {
		t.Fatal("unrelated direct plan was blocked")
	}
}
