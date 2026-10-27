package app

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"testing"
	"time"
)

func TestReviewNFQWS2HookUncertainFencesNextExclusive(t *testing.T) {
	a, _, model := nfqws2HookAppFixture(t)
	model.restore = func(context.Context, dataplane.Plan) (dataplane.NFQWS2HookRestore, error) {
		return dataplane.NFQWS2HookRestore{Class: dataplane.NFQWS2HooksLoss, Reason: dataplane.NFQWS2HookReasonWrite, Uncertain: true, Instance: "instance-a"}, errors.Join(dataplane.ErrNFQWS2HookRestore, dataplane.ErrNFQWS2HookUncertain)
	}
	if err := a.restoreNFQWS2HooksRound(context.Background(), time.Now()); !errors.Is(err, dataplane.ErrNFQWS2HookUncertain) {
		t.Fatal(err)
	}
	_, release, err := a.Operations.ExclusiveContext(context.Background())
	if err == nil {
		release()
		t.Fatal("uncertain kernel cleanup released admission: next exclusive operation was admitted")
	}
	if !errors.Is(err, operationgate.ErrRecovery) {
		t.Fatalf("wrong refusal: %v", err)
	}
}

func TestReviewNFQWS2HookSlowRoundDatesSettlementAtCompletion(t *testing.T) {
	for _, outcome := range []string{"success", "failure"} {
		t.Run(outcome, func(t *testing.T) {
			a, _, model := nfqws2HookAppFixture(t)
			if outcome == "failure" {
				model.restore = nfqws2HookFailure(dataplane.NFQWS2HookReasonQueue)
			}
			// Simulate time already spent in the preceding forwarding recovery and
			// this attempt. No sleep: reconcileRound passes its original start stamp.
			started := time.Now()
			_ = a.restoreNFQWS2HooksRound(context.Background(), started.Add(-71*time.Second))
			a.nfqws2Hooks.mu.Lock()
			b := a.nfqws2Hooks.budget
			a.nfqws2Hooks.mu.Unlock()
			if outcome == "success" && b.restored.Before(started) {
				t.Fatal("successful repair was dated before its invocation; immediate re-loss escapes quick-loss limit")
			}
			if outcome == "failure" && b.next.Before(started.Add(nfqws2HookRetryBase)) {
				t.Fatal("failure backoff was dated from stale round start and is already expired at completion")
			}
		})
	}
}
