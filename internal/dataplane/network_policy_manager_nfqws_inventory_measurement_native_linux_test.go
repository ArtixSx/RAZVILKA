//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package dataplane

import (
	"context"
	"testing"
)

func TestNativeNFQInventoryCountersPreserveFirstReasonAndClose(t *testing.T) {
	c, source, ctx := networkPolicyNFQReadSourcesFixture(t)
	c.readSource = &networkPolicyOriginalInventoryReader{inventory: c.inventory}
	direct, err := CompileNFQWSDirectLANPolicyRuntime(source.execution.plan.LAN.Generation, source.execution.plan.LAN.Ingress)
	if err != nil {
		t.Fatal(err)
	}
	source.execution.plan.LAN = direct
	ctx = networkPolicyConsumerContext(ctx, source.execution.plan)
	before := NativeFixtureNFQInventoryReadCounts()
	// Foreign participant short-circuits even nil LAN/context/dispatcher.
	if c.nfqInventorySources(nil, nil, true) != nil {
		t.Fatal("foreign selection changed")
	}
	if c.nfqInventorySources(context.WithValue(ctx, wgOperationOwnerKey{}, "foreign"), direct, false) != nil {
		t.Fatal("foreign context selection changed")
	}
	if c.nfqInventorySources(ctx, direct, false) == nil {
		t.Fatal("original selector not exercised")
	}
	after := NativeFixtureNFQInventoryReadCounts()
	for name, value := range after {
		want := uint64(0)
		if name == "fallback-foreign-participant" || name == "fallback-wg-owner" || name == "eligible" {
			want = 1
		}
		if value < before[name] || value-before[name] != want {
			t.Fatal("selector evaluated more than first failed predicate", name, before[name], value, want)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	closed := NativeFixtureNFQInventoryReadCounts()
	for name, value := range after {
		if closed[name] != value {
			t.Fatal("Close changed measurement generation", name)
		}
	}
	closed["eligible"] = 0
	if NativeFixtureNFQInventoryReadCounts()["eligible"] != after["eligible"] {
		t.Fatal("snapshot mutation reset process counters")
	}
}

func TestNativeNFQInventoryCounterLabelsClosed(t *testing.T) {
	counts := NativeFixtureNFQInventoryReadCounts()
	if len(counts) != 34 {
		t.Fatal("closed diagnostic vocabulary changed", len(counts))
	}
	if len(nativeNFQInventoryReads) != 35 {
		t.Fatal("closed counter capacity changed")
	}
	before := counts["fallback-nfq-rollback"]
	noteNFQInventoryRead(nfqInventoryContextBase + 15)
	if got := NativeFixtureNFQInventoryReadCounts()["fallback-nfq-rollback"]; got != before+1 {
		t.Fatal("context index and label diverged", got, before)
	}
}
