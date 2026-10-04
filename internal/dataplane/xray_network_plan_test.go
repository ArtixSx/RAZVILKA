package dataplane

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestXrayNodePlanAndCandidateRequireSameNetworkEpoch(t *testing.T) {
	input := Input{NetworkProfileID: "wan-111111111111", Routes: []Route{{ServiceID: "test", Selected: "xray:group-" + strings.Repeat("a", 32), Resolved: "xray:node-" + strings.Repeat("b", 64)}}}
	first, err := BuildAt(input, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	input.NetworkProfileID = "wan-222222222222"
	second, err := BuildAt(input, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	ir := first.RoutePlanFor("xray")
	if first.Digest == second.Digest || !first.RequiresNetworkProof() || !ir.RequiresNetworkProof() || ir.NetworkProfileID != first.NetworkProfileID || first.RoutePlanFor("sing-box").RequiresNetworkProof() {
		t.Fatal("Xray network proof lost or aliased")
	}
	input.NetworkProfileID = ""
	missing, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, b := range missing.Blockers {
		found = found || b.Code == "NETWORK_PROOF_UNAVAILABLE"
	}
	if !found || missing.Ready {
		t.Fatal("missing Xray network epoch accepted")
	}
	var legacy Plan
	if err = json.Unmarshal([]byte(`{"schema_version":1,"state":"committed","routes":[{"resolved_route":"xray:node-old"}]}`), &legacy); err != nil || !legacy.RequiresNetworkProof() {
		t.Fatal("legacy Xray journal gained authority", err)
	}
}
