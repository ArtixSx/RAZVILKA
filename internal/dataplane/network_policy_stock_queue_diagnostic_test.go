package dataplane

import (
	"errors"
	"testing"
)

// Pure fixed-coordinate diagnostics; no native input is retained or printed.
func TestNetworkPolicyStockQueueDiagnosticsPreserveClosedInnerCause(t *testing.T) {
	b, p, image := nfqwsScopedStockImageFixture(t, false)
	identity, _ := networkPolicyIdentityFixture()
	identity.value = image.capture.snapshot.Scope.Network
	e := &nfqws2ActiveExecution{identity: identity, inventory: b.network.inventory}
	o := &networkPolicyStockQueueObservation{execution: e, queue: p.spec.Queue}
	for _, cut := range []string{"source", "owned", "graph"} {
		t.Run(cut, func(t *testing.T) {
			s := nfqwsDirectStockTestClone(image.capture.snapshot)
			var consumers []networkPolicyNFQObservation
			cause := ErrNetworkPolicyConsumers
			switch cut {
			case "source":
				s.Scope.ToolReviewID = "changed"
			case "owned":
				consumers = []networkPolicyNFQObservation{{execution: &nfqws2ActiveExecution{}}}
			case "graph":
				cause = errNFQWSDirectStockQueue
				s.Rows = append(s.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "FORWARD", "-j", "local_delay"))
			}
			_, err := o.comparison(s, consumers)
			outer := lanPolicyPreflightAt("inventory-row-unallowed", err)
			if err == nil || LANPolicyPreflightFailureStage(outer) != "inventory-stock-"+cut || !errors.Is(outer, cause) || outer.Error() != cause.Error() {
				t.Fatal("outer stage hid stock boundary/cause", cut, LANPolicyPreflightFailureStage(outer), outer)
			}
		})
	}
}
