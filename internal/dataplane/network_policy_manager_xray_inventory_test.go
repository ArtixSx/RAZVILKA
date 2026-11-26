package dataplane

import (
	"slices"
	"testing"
)

// These complete-image predicates grant no original runtime or COMMON owner.
func TestNetworkPolicyXrayInventoryRequiresOriginalConsumer(t *testing.T) {
	snapshot, observation := xraySelectedTCPOrderFixture(t)
	stock, err := inspectXrayStockOutputQueues(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	identity := snapshot.Scope.Network
	if err := checkNetworkPolicyInventoryWithStock(snapshot, identity, nil, LANPolicyXraySelectedTCPMode, nil, stock); err == nil {
		t.Fatal("bare predicate accepted unowned RZX")
	}
	check := func(s BackendInventorySnapshot, o networkPolicyXraySelectedTCPObservation) error {
		return checkNetworkPolicyInventoryWithXray(s, identity, nil, LANPolicyXraySelectedTCPMode, nil, stock, nil, []networkPolicyXraySelectedTCPObservation{o})
	}
	if err := check(snapshot, observation); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"missing-required", "duplicate", "foreign-v6", "foreign-table", "foreign-chain", "unknown-option", "required-shape"} {
		t.Run(change, func(t *testing.T) {
			s := nfqwsDirectStockTestClone(snapshot)
			o := observation
			index := -1
			for i, row := range s.Rows {
				if networkPolicyXraySelectedTCPRow(row) && row.Tokens[0] == "-A" {
					index = i
					break
				}
			}
			if index < 0 {
				t.Fatal("fixture lacks body")
			}
			switch change {
			case "missing-required":
				s.Rows = slices.Delete(s.Rows, index, index+1)
			case "duplicate":
				s.Rows = append(s.Rows, s.Rows[index])
			case "foreign-v6":
				s.Rows[index].Family = 6
			case "foreign-table":
				s.Rows[index].Table = "mangle"
			case "foreign-chain":
				s.Rows[index].Tokens[1] = "RZX_foreign"
			case "unknown-option":
				s.Rows[index].Tokens = append(s.Rows[index].Tokens, "--unreviewed", "1")
			case "required-shape":
				o.required = o.required[:len(o.required)-1]
			}
			if err := check(s, o); err == nil {
				t.Fatal("unsafe image accepted")
			}
		})
	}
}

func TestNetworkPolicyReservedXrayRowsCannotHideInAnotherMode(t *testing.T) {
	for _, tokens := range [][]string{{"-N", "RZX_foreign"}, {"-A", "PREROUTING", "-j", "RZX_foreign"}, {"-A", "OUTPUT", "-p", "tcp", "--goto=RZX_foreign"}} {
		for _, mode := range []string{"", LANPolicyNFQWSDirectMode, LANPolicyXraySelectedTCPMode, LANPolicyManagedListDirectMode} {
			reserved, err := networkPolicyReservedRowForMode(tokens, mode)
			if err != nil || !reserved {
				t.Fatal("Xray coordinate escaped reserved inventory", mode, tokens, err)
			}
		}
	}
}
