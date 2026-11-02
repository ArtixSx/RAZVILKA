package dataplane

import (
	"context"
	"testing"
)

// Association tests only; the native LAN workflow executes both actual full
// captures. No model row may claim a real namespace observation here.
func TestNFQWSActiveInventoryReadRequiresUnmixedOriginalProducer(t *testing.T) {
	for _, mode := range []string{"original", "readonly-copy", "mixed-callback", "foreign-network", "foreign-runner", "foreign-plan", "foreign-context", "copied-owner", "source-drift", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			e, ctx := nfqwsActiveCommandFixture(t)
			e.material.execution, e.material.executionBound = e, true
			e.inventory.reader.Runner = &nfqwsFakeRunner{}
			e.inventory.reader.Provider = e.material.provider
			b := e.binding
			b.activeReadback = e
			b.network = &nfqwsScopedNetworkBinding{provider: e.material.provider, inventory: e.inventory}
			p := e.resource.Plan()
			switch mode {
			case "readonly-copy":
				copy := *b
				b = &copy
			case "mixed-callback":
				b.AdditionalReadback = func(context.Context, *NFQWSScopedPlan) error { t.Fatal("mixed callback invoked"); return nil }
			case "foreign-network":
				copy := *b
				b = &copy
				b.network = &nfqwsScopedNetworkBinding{provider: e.material.provider, inventory: e.inventory}
			case "foreign-runner":
				b.Runner = &nfqwsFakeRunner{}
			case "foreign-plan":
				p = &NFQWSScopedPlan{}
			case "foreign-context":
				ctx = context.Background()
			case "copied-owner":
				b.activeReadback = &nfqws2ActiveExecution{self: e, material: e.material, resource: e.resource, binding: e.binding}
			case "source-drift":
				e.material.execution = &nfqws2ActiveExecution{}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got, err := b.activeReadbackOwner(ctx, p)
			valid := mode == "original" || mode == "readonly-copy"
			if valid && (err != nil || got != e) || !valid && err == nil {
				t.Fatal("original active read association", mode, err)
			}
			if !valid {
				image, err := b.readActiveRules(ctx, p)
				if err == nil || image.capture != nil || image.rules != nil {
					t.Fatal("invalid owner produced inventory", err)
				}
			}
		})
	}
}
