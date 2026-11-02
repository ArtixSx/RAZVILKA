//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/privaterestore"
)

// Actual protected original execution writers and fresh Manager readers.
// Native cleanup outcomes here are documentary models, never a native grant.
func TestMihomoSameBootOriginalActiveFenceSurvivesEveryNativePhaseAndPartialTerminal(t *testing.T) {
	sameBootInputsFixture(t, func(ctx context.Context, set *privaterestore.OfflineServiceControlSet, state string, e Execution) {
		i, err := holdMihomoSameBootInputs(ctx, set, state, e.PlanID, e.Digest)
		if err != nil {
			t.Fatal(err)
		}
		defer i.close()
		assertActive := func(stage string) {
			t.Helper()
			// The public journal fence is the contract. Which original-owner
			// check detects this documentary ACTIVE row first is independent.
			if err := New(state).CheckExecutionRecovery(ctx); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("original active resource fence missing", stage, err)
			}
		}
		for _, stage := range []string{"before-signal", "sidecar-exited", "policy-removed", "forwarding-removed", "archive-frozen"} {
			assertActive(stage)
		}
		after, err := mihomoLiveRetirementTerminal(e, time.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(after)
		if err != nil {
			t.Fatal(err)
		}
		current := func() error { return i.current(ctx) }
		if err := i.records[0].publish(raw, current); err != nil {
			t.Fatal(err)
		}
		if err := New(state).CheckExecutionRecovery(ctx); !errors.Is(err, ErrExecutionJournal) {
			t.Fatal("partial terminal pair released installer fence", err)
		}
		if err := i.records[1].publish(raw, current); err != nil {
			t.Fatal(err)
		}
		if err := New(state).CheckExecutionRecovery(ctx); err != nil {
			t.Fatal("two genuine terminal ACKs remain blocked", err)
		}
	})
}
