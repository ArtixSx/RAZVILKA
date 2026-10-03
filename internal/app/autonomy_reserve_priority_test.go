package app

import "testing"

func TestRefillDoesNotDelayAuthorizedRecoveryWithReadyPeer(t *testing.T) {
	for _, due := range []bool{false, true} {
		if refillBeforeApply(false, true, 1, 3, due) {
			t.Fatal("background refill delayed fresh peer recheck and Apply")
		}
	}
}
func TestRefillStillSearchesColdAndMaintainsHealthyPath(t *testing.T) {
	for _, tc := range []struct {
		healthy, replace bool
		ready, target    int
		due              bool
	}{
		{false, true, 0, 3, false}, {true, false, 1, 3, false},
		{true, false, 3, 3, true}, {false, false, 1, 3, true},
	} {
		if !refillBeforeApply(tc.healthy, tc.replace, tc.ready, tc.target, tc.due) {
			t.Fatal(tc)
		}
	}
	if refillBeforeApply(true, false, 3, 3, false) {
		t.Fatal("unnecessary refill")
	}
}
