package dataplane

import (
	"reflect"
	"testing"
)

// Compiler and startup-profile comparisons only; no consumer, receipt,
// process or execution admission is constructed by these mode tests.
func TestLANPolicyXraySelectedModeSealsOriginalIngressWithoutGateEffects(t *testing.T) {
	original := lanRuntimeFixture(t)
	nfq, err := CompileNFQWSDirectLANPolicyRuntime(original.Generation, original.Ingress)
	if err != nil {
		t.Fatal(err)
	}
	xray, err := CompileXraySelectedTCPLANPolicyRuntime(original.Generation, original.Ingress)
	if err != nil || xray.Mode != LANPolicyXraySelectedTCPMode || xray.Digest == original.Digest || xray.Digest == nfq.Digest || !reflect.DeepEqual(xray.Ingress, original.Ingress) {
		t.Fatal("Xray mode failed to seal distinct original physical intent", err)
	}
	if effects, err := xray.Effects(); err != nil || len(effects) != 0 || len(lanPolicyChains(xray)) != 0 || len(lanPolicyRules(xray)) != 0 {
		t.Fatal("Xray gate installed a mark, RPDB rule or selector", err)
	}
	if _, err := LANPolicyEffectsPlan(xray); err == nil {
		t.Fatal("empty gate definition supplied a COMMON effect receipt")
	}
	for _, mode := range []string{"", LANPolicyNFQWSDirectMode, LANPolicyManagedListDirectMode} {
		changed := CloneLANPolicyRuntime(xray)
		changed.Mode = mode
		if ValidateLANPolicyRuntime(changed) == nil {
			t.Fatal("another mode reused the Xray seal")
		}
	}
	if _, err := compileLANPolicyRuntime(original.Generation, original.Ingress, LANPolicyManagedListDirectMode); err == nil {
		t.Fatal("startup profile became a packet plan mode")
	}
	for _, routes := range [][]Route{nil, {{Resolved: "nfqws2", NetworkPolicyGeneration: xray.Generation}}, {{Resolved: "xray:node", Domains: []string{"example.com"}, NetworkPolicyGeneration: xray.Generation}}} {
		if ValidateNetworkPolicyLAN(xray, routes) == nil {
			t.Fatal("Xray selected mode accepted missing/foreign/domain intent")
		}
	}
}

func TestNetworkPolicySharedDirectProfilePreservesStandaloneModeBoundary(t *testing.T) {
	shared := &networkPolicyIdentity{mode: LANPolicyManagedListDirectMode}
	for _, mode := range []string{LANPolicyNFQWSDirectMode, LANPolicyXraySelectedTCPMode} {
		if !shared.acceptsMode(mode) || shared.inventoryMode(&LANPolicyRuntimePlan{Mode: mode}) != mode {
			t.Fatal("shared profile lost the original concrete plan mode")
		}
		standalone := &networkPolicyIdentity{mode: mode}
		other := LANPolicyNFQWSDirectMode
		if mode == other {
			other = LANPolicyXraySelectedTCPMode
		}
		if standalone.acceptsMode(other) || standalone.acceptsMode("") || standalone.acceptsMode(LANPolicyManagedListDirectMode) {
			t.Fatal("standalone owner broadened to another producer")
		}
	}
	for _, mode := range []string{"", LANPolicyManagedListDirectMode, "caller-defined"} {
		if shared.acceptsMode(mode) {
			t.Fatal("startup profile admitted an unsupported plan mode")
		}
	}
	if shared.inventoryMode(nil) != LANPolicyManagedListDirectMode {
		t.Fatal("absence observation borrowed an engine's queue reservation")
	}
	if (&networkPolicyIdentity{}).acceptsMode(LANPolicyXraySelectedTCPMode) {
		t.Fatal("legacy owner adopted a selected consumer")
	}
}
