package dataplane

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLANPolicyDirectModeSealsIntentWithoutNativeEffectsOrEmptyReceiptGrant(t *testing.T) {
	legacy := lanRuntimeFixture(t)
	direct, err := CompileNFQWSDirectLANPolicyRuntime(legacy.Generation, legacy.Ingress)
	if err != nil || direct.Digest == legacy.Digest || direct.Mode != LANPolicyNFQWSDirectMode {
		t.Fatal("direct mode missing from immutable identity", err)
	}
	if effects, err := direct.Effects(); err != nil || len(effects) != 0 || len(lanPolicyChains(direct)) != 0 || len(lanPolicyRules(direct)) != 0 {
		t.Fatal("consumer intent manufactured native gate effects", err, effects)
	}
	if _, err := LANPolicyEffectsPlan(direct); err == nil {
		t.Fatal("mode relaxed general empty mixed receipt rejection")
	}
	image, err := json.Marshal(legacy)
	if err != nil || strings.Contains(string(image), "mode") {
		t.Fatal("legacy compiler image changed", err)
	}
	copy := CloneLANPolicyRuntime(direct)
	copy.Ingress[0].Sources[0] = "192.168.99.0/24"
	if ValidateLANPolicyRuntime(copy) == nil || ValidateLANPolicyRuntime(direct) != nil {
		t.Fatal("copied or changed intent retained the seal")
	}
	copy = CloneLANPolicyRuntime(direct)
	copy.Mode = ""
	if ValidateLANPolicyRuntime(copy) == nil {
		t.Fatal("mode downgrade reused direct seal")
	}
}

func TestLANPolicyDirectModeRefusesOtherConsumersAndMissingRoutes(t *testing.T) {
	lan := lanRuntimeFixture(t)
	lan, err := CompileNFQWSDirectLANPolicyRuntime(lan.Generation, lan.Ingress)
	if err != nil {
		t.Fatal(err)
	}
	for _, routes := range [][]Route{
		nil,
		{{Resolved: "wireguard:node", NetworkPolicyGeneration: lan.Generation}},
		{{Resolved: "xray:node", NetworkPolicyGeneration: lan.Generation}},
		{{Resolved: "nfqws2", Domains: []string{"example.com"}, NetworkPolicyGeneration: lan.Generation}},
	} {
		if ValidateNetworkPolicyLAN(lan, routes) == nil {
			t.Fatal("direct NFQ mode widened to another consumer", routes)
		}
	}
}
