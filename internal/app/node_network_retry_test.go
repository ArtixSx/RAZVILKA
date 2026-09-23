package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

func TestNodeNetworkRetryDiscardsOldResultsAndRechecksFrozenSelection(t *testing.T) {
	a, q := durableNodeFixture(t, 3)
	profile := "wan-0123456789ab"
	a.FreshProfile = func(context.Context) (string, error) { return profile, nil }
	var seen []string
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		seen = append(seen, r.NodeID)
		if profile == "wan-abcdef012345" {
			p := a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
			if p.State != "running" || p.EarlierNetworkCompleted != 1 {
				t.Error("live view lost historical count", p)
			}
		}
		return autofallbackResult(r, true), nil
	})
	id := enqueueNodeFixture(t, a, q)
	a.runDurableServiceJob(context.Background(), time.Now())
	old := a.nodeBatchMemoryResults()[id]
	if old.Passed != 1 {
		t.Fatal("missing first observation")
	}
	profile = "wan-abcdef012345"
	a.runDurableServiceJob(context.Background(), time.Now().Add(2*time.Second))
	j := durableJobAt(t, a, id)
	if j.State != "queued" || j.Cursor != 1 || j.CheckEpochStart != 1 || j.CheckNetwork != "" || j.CleanupOutcome != "joined" || j.Attempts != 1 || j.NotBefore.Before(time.Now().Add(28*time.Second)) {
		t.Fatal(j)
	}
	if a.runDurableServiceJob(context.Background(), j.NotBefore.Add(-time.Second)) {
		t.Fatal("ignored cooldown")
	}
	if enqueueNodeFixture(t, a, q) != id {
		t.Fatal("retry changed identity")
	}
	// Model a read that copied the old results before the journal reset.
	a.nodeChecks.batchResults[id] = &old
	p := a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if len(p.Results) != 0 || p.Passed != 0 || p.EarlierNetworkCompleted != 1 || !strings.Contains(p.Message, "повтор") {
		t.Fatal("old epoch leaked", p)
	}
	delete(a.nodeChecks.batchResults, id)
	a.runDurableServiceJob(context.Background(), j.NotBefore)
	if durableJobAt(t, a, id).Attempts != 0 {
		t.Fatal("next item inherited previous retry budget")
	}
	for round := 0; round < 3 && !durableJobAt(t, a, id).terminal(); round++ {
		a.runDurableServiceJob(context.Background(), time.Now().Add(3*time.Second))
	}
	p = a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if p.State != "completed" || p.Completed != 3 || p.EarlierNetworkCompleted != 1 || p.Passed != 2 || len(p.Results) != 2 || !reflect.DeepEqual(seen, q.NodeIDs) {
		t.Fatal(p, seen)
	}
	for _, result := range p.Results {
		if result.NetworkProfile != "wan-abcdef012345" {
			t.Fatal("mixed epochs")
		}
	}
}

func TestNodeNetworkRetryBoundAndDelaySurviveRestart(t *testing.T) {
	a, q := durableNodeFixture(t, 1)
	a.FreshProfile = func(context.Context) (string, error) { return "", systemprobe.ErrNetworkUnavailable }
	id := enqueueNodeFixture(t, a, q)
	a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		t.Error("unobserved network reached checker")
		return dataplane.NodeCheckResult{}, nil
	})
	a.runDurableServiceJob(context.Background(), time.Now())
	first := durableJobAt(t, a, id)
	b := &App{Store: a.Store, Nodes: a.Nodes, Catalog: a.Catalog, FreshProfile: a.FreshProfile, NodeChecker: a.NodeChecker}
	b.StartNodeChecks(context.Background())
	t.Cleanup(func() { _ = b.WaitNodeChecks(context.Background()) })
	b.reconciler.started, b.reconciler.path = true, a.Store.AutomationStatePath()
	if err := b.loadReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := range b.reconciler.doc.Operations {
		b.reconciler.doc.Operations[i].NextRun = time.Now().Add(time.Hour)
	}
	if got := durableJobAt(t, b, id); got.Attempts != 1 || !got.NotBefore.Equal(first.NotBefore) {
		t.Fatal("restart erased backoff", got)
	}
	b.runDurableServiceJob(context.Background(), first.NotBefore)
	second := durableJobAt(t, b, id)
	if second.Attempts != 2 || second.State != "queued" || second.NotBefore.Before(time.Now().Add(58*time.Second)) {
		t.Fatal(second)
	}
	if b.runDurableServiceJob(context.Background(), second.NotBefore.Add(-time.Second)) {
		t.Fatal("second cooldown skipped")
	}
	b.runDurableServiceJob(context.Background(), second.NotBefore)
	last := durableJobAt(t, b, id)
	if last.State != "failed" || last.Attempts != 3 || last.Reason != "network-unconfirmed" {
		t.Fatal("retry was not bounded", last)
	}
	if b.runDurableServiceJob(context.Background(), time.Now().Add(time.Hour)) {
		t.Fatal("terminal retry replayed")
	}
	if validateDurableServiceJobs(b.reconciler.doc.Jobs) != nil {
		t.Fatal("invalid retry journal")
	}
	corrupt := last
	corrupt.CheckEpochStart = last.Cursor + 1
	if validateDurableServiceJobs([]durableServiceJob{corrupt}) == nil {
		t.Fatal("accepted historical count beyond completed cursor")
	}
}

func TestNodeNetworkRetryAfterProbeStillHonorsCancelAndCleanup(t *testing.T) {
	for _, mode := range []string{"retry", "cancel", "cleanup"} {
		t.Run(mode, func(t *testing.T) {
			a, q := durableNodeFixture(t, 1)
			profile := "wan-0123456789ab"
			a.FreshProfile = func(context.Context) (string, error) { return profile, nil }
			id := enqueueNodeFixture(t, a, q)
			a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				profile = "wan-abcdef012345"
				if mode == "cancel" {
					if ok, err := a.cancelDurableServiceJob(ctx, id); !ok || err != nil {
						t.Fatal(ok, err)
					}
				}
				if mode == "cleanup" {
					return dataplane.NodeCheckResult{ErrorCode: "node-cleanup-failed"}, errors.New("cleanup failed")
				}
				return autofallbackResult(r, true), nil
			})
			a.runDurableServiceJob(context.Background(), time.Now())
			j := durableJobAt(t, a, id)
			switch mode {
			case "retry":
				if j.State != "queued" || j.Cursor != 0 || len(a.nodeBatchMemoryResults()) != 0 {
					t.Fatal(j)
				}
			case "cancel":
				if j.State != "canceled" {
					t.Fatal("cancel replayed", j)
				}
			case "cleanup":
				if j.State != "failed" || j.CleanupOutcome != "unverified" || !a.Operations.Snapshot().Fenced {
					t.Fatal("unverified cleanup replayed", j)
				}
			}
		})
	}
}
