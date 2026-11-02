package startuptools

import "testing"

func TestObservedPolicyIPReadMatchesOnlyExistingPolicyInspection(t *testing.T) {
	for _, stock := range []bool{false, true} {
		for _, family := range []string{"-4", "-6"} {
			args := []string{family, "-N", "rule", "show"}
			if stock {
				args = []string{family, "rule", "show"}
			}
			if !observedPolicyIPRead(stock, args) {
				t.Fatal("existing fixed rule reader refused", stock, args)
			}
		}
		for _, args := range [][]string{nil, {"rule", "show"}, {"-4", "route", "show"}, {"-4", "rule", "del"}, {"-4", "-N", "rule", "delete"}, {"-4", "-N", "rule", "flush"}, {"-4", "-N", "rule", "show", "table", "123"}, {"-4", "-N", "-N", "rule", "show"}, {"-j", "rule", "show"}, {"-4", "rule", "show", ";"}} {
			if observedPolicyIPRead(stock, args) {
				t.Fatal("inspection ABI widened", stock, args)
			}
		}
	}
	if observedPolicyIPRead(false, []string{"-4", "rule", "show"}) || observedPolicyIPRead(true, []string{"-4", "-N", "rule", "show"}) {
		t.Fatal("profile translation crossed")
	}
}
