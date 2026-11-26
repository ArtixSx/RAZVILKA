package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

func TestExactNodeRealityRuntimeDefaultMatchesEffectiveContract(t *testing.T) {
	request := checkedNodeRequest()
	request.Outbound = []byte(`{"type":"vless","server":"node.example","server_port":443,"uuid":"private","tls":{"enabled":true,"server_name":"front.example","reality":{"enabled":true,"public_key":"private-key"}}}`)
	before := bytes.Clone(request.Outbound)
	endpoint, err := inspectExactNodeOutbound(request.Outbound)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Pinned = netip.MustParseAddr("203.0.113.8")
	data, err := compilePinnedSingBoxNodeConfig(request.Outbound, endpoint, 19181)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	_ = json.Unmarshal(data, &doc)
	utls := doc.Outbounds[0]["tls"].(map[string]any)["utls"].(map[string]any)
	if utls["enabled"] != true || utls["fingerprint"] != "chrome" || !bytes.Equal(before, request.Outbound) {
		t.Fatal("checker default or canonical mismatch")
	}
	checker := fakeExactNodeChecker(t)
	result, err := checker.Check(context.Background(), request)
	if err != nil || !result.Available || result.RuntimeContract != providerprofile.SingBoxRealityUTLSContract {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	checker.engine = "xray"
	result, _ = checker.Check(context.Background(), request)
	if result.RuntimeContract != "" {
		t.Fatal("Sing-box contract leaked to Xray check")
	}
	result, _ = fakeExactNodeChecker(t).Check(context.Background(), checkedNodeRequest())
	if result.RuntimeContract != "" {
		t.Fatal("unrelated profile gained contract")
	}
}
