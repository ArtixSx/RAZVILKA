//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
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
	if len(counts) != 57 {
		t.Fatal("closed diagnostic vocabulary changed", len(counts))
	}
	if len(nativeNFQInventoryReads) != 58 {
		t.Fatal("closed counter capacity changed")
	}
	before := counts["fallback-nfq-rollback"]
	noteNFQInventoryRead(nfqInventoryContextBase + 15)
	if got := NativeFixtureNFQInventoryReadCounts()["fallback-nfq-rollback"]; got != before+1 {
		t.Fatal("context index and label diverged", got, before)
	}
}

// Err is observed only at the original short-circuit boundary.
type nativeNFQOwnerDiagnosticContext struct {
	context.Context
	result error
	calls  int
}

func (c *nativeNFQOwnerDiagnosticContext) Err() error { c.calls++; return c.result }

func TestNativeNFQInventoryOwnerReasonUsesOriginalErrRead(t *testing.T) {
	for _, mode := range []string{"missing", "invalid", "no-activation", "deadline", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			activation := &nativeNFQOwnerDiagnosticContext{Context: context.Background()}
			p := &NFQWSPreparedHandle{owner: &nfqws2ActiveOwner{state: "prepared", activation: activation}}
			p.owner.prepared = p
			label := "owner-opening-" + mode
			wantCalls := 0
			switch mode {
			case "missing":
				p.owner = nil
				label = "owner-missing"
			case "invalid":
				p.owner.stopRequested = true
			case "no-activation":
				p.owner.activation = nil
			case "deadline":
				activation.result = context.DeadlineExceeded
				wantCalls = 1
			case "canceled":
				activation.result = context.Canceled
				wantCalls = 1
			}
			before := NativeFixtureNFQInventoryReadCounts()
			err := p.VerifyOwnerObservation(context.Background(), NFQWSActiveObservation{})
			if !errors.Is(err, ErrNFQWSManagedProcessUnknown) || activation.calls != wantCalls {
				t.Fatal("original refusal/Err read changed", err, activation.calls, wantCalls)
			}
			after := NativeFixtureNFQInventoryReadCounts()
			for k, v := range after {
				want := uint64(0)
				if k == label {
					want = 1
				}
				if v-before[k] != want {
					t.Fatal("first owner reason changed", k, v-before[k], want)
				}
			}
		})
	}
}

func TestNativeNFQInventorySourceReasonOnlyWholeSelector(t *testing.T) {
	for _, mode := range []string{"coordinates", "execution", "resource-binding", "observer", "retired", "association"} {
		t.Run(mode, func(t *testing.T) {
			c, s, ctx := networkPolicyNFQReadSourcesFixture(t)
			switch mode {
			case "coordinates":
				c.inventory = nil
			case "execution":
				ctx = context.WithValue(ctx, nfqws2ActiveExecutionKey{}, "foreign")
			case "resource-binding":
				s.execution.resource = nil
			case "observer":
				s.execution.inventory.reader.Runner = nfqws2RunFunc(func(context.Context, string, ...string) ([]byte, error) {
					t.Fatal("source diagnostics ran command")
					return nil, nil
				})
			case "retired":
				s.execution.retired = true
			case "association":
				s.adapter.activeExecution = nil
			}
			before := NativeFixtureNFQInventoryReadCounts()
			if c.nfqReadSources(ctx) != nil || c.nfqReadSourcesDiagnostic(ctx, true) != nil {
				t.Fatal("source refusal changed")
			}
			after := NativeFixtureNFQInventoryReadCounts()
			for k, v := range after {
				want := uint64(0)
				if k == "source-"+mode {
					want = 1
				}
				if v-before[k] != want {
					t.Fatal("narrow read duplicated whole-selector reason", k, v-before[k], want)
				}
			}
		})
	}
}
