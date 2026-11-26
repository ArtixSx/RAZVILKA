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
			stage := "inventory-stock-" + cut
			switch cut {
			case "source":
				s.Scope.ToolReviewID = "changed"
			case "owned":
				consumers = []networkPolicyNFQObservation{{execution: &nfqws2ActiveExecution{}}}
			case "graph":
				cause = errNFQWSDirectStockQueue
				stage += "-reachability"
				s.Rows = append(s.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "FORWARD", "-j", "local_delay"))
			}
			_, err := o.comparison(s, consumers)
			outer := lanPolicyPreflightAt("inventory-row-unallowed", err)
			if err == nil || LANPolicyPreflightFailureStage(outer) != stage || !errors.Is(outer, cause) || outer.Error() != err.Error() {
				t.Fatal("outer stage hid stock boundary/cause", cut, LANPolicyPreflightFailureStage(outer), outer)
			}
		})
	}
}

func TestNetworkPolicyStockGraphDiagnosticAcceptsOnlyPrivateFixedLeaf(t *testing.T) {
	for _, kind := range []nfqwsDirectStockFailureKind{nfqwsDirectStockParse, nfqwsDirectStockShape, nfqwsDirectStockReachabilityFailure, nfqwsDirectStockCollision, nfqwsDirectStockUnknownOption, nfqwsDirectStockCoverage, nfqwsDirectStockBudgetFailure, nfqwsDirectStockOwned} {
		cause := nfqwsDirectStockFailure(kind)
		outer := lanPolicyPreflightAt("inventory-row-unallowed", networkPolicyStockGraphFailure(cause))
		if got := LANPolicyPreflightFailureStage(outer); got != "inventory-stock-graph-"+kind.label() || !errors.Is(outer, errNFQWSDirectStockQueue) || outer.Error() != cause.Error() {
			t.Fatal("fixed graph leaf/cause lost through outer inventory refusal", got)
		}
	}
	for _, cause := range []error{errors.New("inventory-stock-graph-reachability"), errNFQWSDirectStockQueue, nfqwsDirectStockFailure(255)} {
		outer := networkPolicyStockGraphFailure(cause)
		if LANPolicyPreflightFailureStage(outer) != "inventory-stock-graph" || !errors.Is(outer, cause) {
			t.Fatal("unrecognized cause supplied a graph leaf")
		}
	}
	if networkPolicyStockGraphFailure(nil) != nil {
		t.Fatal("successful comparison acquired a refusal")
	}
}
