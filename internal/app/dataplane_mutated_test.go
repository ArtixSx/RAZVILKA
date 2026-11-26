package app

import (
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestDataplaneExecutionMutatedCountsOnlyNetworkChangingSteps(t *testing.T) {
	for phase, want := range map[string]bool{"snapshot": false, "stage": false, "validate": false, "canary": false, "rollback": false, "verify-rollback": false, "activate": true, "deactivate": true, "commit-adapter": true} {
		got := dataplaneExecutionMutated(dataplane.Execution{Steps: []dataplane.ExecutionStep{{Adapter: "lan-policy", Phase: phase, State: "passed"}}})
		if got != want {
			t.Fatal("mutation classification", phase, got)
		}
	}
	if dataplaneExecutionMutated(dataplane.Execution{}) {
		t.Fatal("empty execution classified as mutated")
	}
}
