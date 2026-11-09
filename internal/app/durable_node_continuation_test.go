package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func takeContinuationWake(t *testing.T, a *App, want bool) {
	t.Helper()
	select {
	case <-a.reconciler.wake:
		if !want {
			t.Fatal("unexpected continuation wake")
		}
	default:
		if want {
			t.Fatal("successful checkpoint did not wake next turn")
		}
	}
}

func TestDurableNodeContinuationPersistsAndReleasesBeforeNextTurn(t *testing.T) {
	a, request := durableNodeFixture(t, 2)
	id := enqueueNodeFixture(t, a, request)
	a.reconciler.wake = make(chan struct{}, 1)
	calls := 0
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls++
		return autofallbackResult(r, true), nil
	})
	a.runDurableServiceJob(context.Background(), time.Now())
	takeContinuationWake(t, a, true)
	job := durableJobAt(t, a, id)
	if calls != 1 || job.Cursor != 1 || job.State != "queued" || job.CleanupOutcome != "joined" || job.NotBefore.After(time.Now()) || job.Attempts != 0 {
		t.Fatal("continuation drained batch or retained idle floor", calls, job)
	}
	raw, err := os.ReadFile(a.Store.AutomationStatePath())
	if err != nil {
		t.Fatal(err)
	}
	var saved reconcilerDocument
	if json.Unmarshal(raw, &saved) != nil || len(saved.Jobs) != 1 || saved.Jobs[0].Cursor != 1 || saved.Jobs[0].State != "queued" || saved.Jobs[0].CleanupOutcome != "joined" {
		t.Fatal("wake preceded durable completion", string(raw))
	}
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal("continuation retained old operation owner", err)
	}
	release()
	// No clock advance, sleep, recursive worker or replacement queue.
	a.runDurableServiceJob(context.Background(), time.Now())
	takeContinuationWake(t, a, false)
	if job := durableJobAt(t, a, id); calls != 2 || job.State != "completed" || job.Cursor != 2 {
		t.Fatal("immediate ordinary turn did not complete", calls, job)
	}
}

func TestDurableNodeContinuationFailedCheckpointDoesNotWake(t *testing.T) {
	a, request := durableNodeFixture(t, 2)
	id := enqueueNodeFixture(t, a, request)
	a.reconciler.wake = make(chan struct{}, 1)
	var writer *restorejournal.FileTarget
	calls := 0
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls++
		var err error
		writer, err = restorejournal.OpenFileTarget(a.reconciler.path)
		return autofallbackResult(r, true), err
	})
	a.runDurableServiceJob(context.Background(), time.Now())
	if writer == nil {
		t.Fatal("checker not dispatched")
	}
	defer writer.Close()
	takeContinuationWake(t, a, false)
	if job := durableJobAt(t, a, id); !a.reconciler.blocked || !a.reconciler.retryAdmission || job.Cursor != 1 || job.State != "queued" {
		t.Fatal("lost checkpoint fence", job)
	}
	a.runDurableServiceJob(context.Background(), time.Now())
	if calls != 1 {
		t.Fatal("unpersisted cursor dispatched next node")
	}
}

func TestDurableNodeContinuationPreservesRecoveryAndBurstYield(t *testing.T) {
	a, request := durableNodeFixture(t, 5)
	id := enqueueNodeFixture(t, a, request)
	a.reconciler.wake = make(chan struct{}, 1)
	a.runDurableServiceJob(context.Background(), time.Now())
	takeContinuationWake(t, a, true)
	for i := range a.reconciler.doc.Operations {
		if a.reconciler.doc.Operations[i].Kind == "node-recovery" {
			a.reconciler.doc.Operations[i].NextRun = time.Now().Add(-time.Second)
		}
	}
	if a.runDurableServiceJob(context.Background(), time.Now()) || durableJobAt(t, a, id).Cursor != 1 {
		t.Fatal("ready continuation overtook recovery")
	}
	takeContinuationWake(t, a, false)
	for i := range a.reconciler.doc.Operations {
		a.reconciler.doc.Operations[i].NextRun = time.Now().Add(time.Hour)
	}
	for want := 2; want <= 3; want++ {
		a.runDurableServiceJob(context.Background(), time.Now())
		takeContinuationWake(t, a, true)
		if durableJobAt(t, a, id).Cursor != want {
			t.Fatal("not one bounded step per turn")
		}
	}
	if a.runDurableServiceJob(context.Background(), time.Now()) || durableJobAt(t, a, id).Cursor != 3 || a.reconciler.durableBurst != 0 {
		t.Fatal("three-step burst no longer yields")
	}
	takeContinuationWake(t, a, false)
	a.runDurableServiceJob(context.Background(), time.Now())
	if durableJobAt(t, a, id).Cursor != 4 {
		t.Fatal("yield lost accepted continuation")
	}
}

func TestDurableNodeContinuationRechecksCancelWANAndBusy(t *testing.T) {
	for _, kind := range []string{"cancel", "wan", "busy"} {
		t.Run(kind, func(t *testing.T) {
			a, request := durableNodeFixture(t, 2)
			id := enqueueNodeFixture(t, a, request)
			a.reconciler.wake = make(chan struct{}, 1)
			calls := 0
			a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				calls++
				return autofallbackResult(r, true), nil
			})
			a.runDurableServiceJob(context.Background(), time.Now())
			takeContinuationWake(t, a, true)
			switch kind {
			case "cancel":
				response := controlRequest(a, "DELETE", fmt.Sprintf("/api/v1/node-checks/current?job_id=%d", id), nil)
				if response.Code != 200 {
					t.Fatal(response.Code, response.Body.String())
				}
			case "wan":
				a.FreshProfile = func(context.Context) (string, error) { return "wan-new", nil }
			case "busy":
				release, err := a.Operations.Exclusive(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			}
			// Discard an ordinary cancellation wake, if any; examine worker continuation only.
			select {
			case <-a.reconciler.wake:
			default:
			}
			before := time.Now()
			a.runDurableServiceJob(context.Background(), before)
			takeContinuationWake(t, a, false)
			job := durableJobAt(t, a, id)
			if calls != 1 || job.Cursor != 1 {
				t.Fatal("continuation reused stale admission", calls, job)
			}
			switch kind {
			case "cancel":
				if job.State != "canceled" {
					t.Fatal(job)
				}
			case "wan":
				if job.State != "queued" || job.Reason != "network-unconfirmed" || job.Attempts != 1 || job.NotBefore.Before(before.Add(30*time.Second)) {
					t.Fatal("WAN backoff weakened", job)
				}
			case "busy":
				if job.State != "queued" || job.Attempts != 0 || job.NotBefore.Before(before.Add(5*time.Second)) {
					t.Fatal("busy backoff weakened", job)
				}
			}
		})
	}
}

func TestDurableNodeContinuationCASConflictDoesNotWakeOrOverwrite(t *testing.T) {
	a, request := durableNodeFixture(t, 2)
	id := enqueueNodeFixture(t, a, request)
	a.reconciler.wake = make(chan struct{}, 1)
	const foreign = "foreign-writer-image"
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		err := os.WriteFile(a.reconciler.path, []byte(foreign), 0600)
		return autofallbackResult(r, true), err
	})
	a.runDurableServiceJob(context.Background(), time.Now())
	takeContinuationWake(t, a, false)
	raw, err := os.ReadFile(a.reconciler.path)
	if err != nil || string(raw) != foreign || !a.reconciler.blocked || a.reconciler.retryAdmission || durableJobAt(t, a, id).Cursor != 1 {
		t.Fatal("CAS conflict bypassed fence or overwrote foreign state", err)
	}
}

func TestDurableNodeContinuationRestartDiscardsPriorProofAndCursor(t *testing.T) {
	a, request := durableNodeFixture(t, 2)
	id := enqueueNodeFixture(t, a, request)
	a.reconciler.wake = make(chan struct{}, 1)
	a.runDurableServiceJob(context.Background(), time.Now())
	takeContinuationWake(t, a, true)
	b := &App{Store: a.Store, Nodes: a.Nodes, Catalog: a.Catalog, FreshProfile: a.FreshProfile}
	root, cancel := context.WithCancel(context.Background())
	b.StartNodeChecks(root)
	t.Cleanup(func() { cancel(); _ = b.WaitNodeChecks(context.Background()) })
	b.reconciler.started, b.reconciler.path = true, a.reconciler.path
	if err := b.loadReconcilerLocked(root); err != nil {
		t.Fatal(err)
	}
	view := b.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if job := durableJobAt(t, b, id); job.Cursor != 0 || job.CheckNetwork != "" || len(view.Results) != 0 || view.Passed != 0 {
		t.Fatal("restart replayed current-process proof", job, view)
	}
	// Model completed initial recovery exactly as the existing restart fixture.
	for i := range b.reconciler.doc.Operations {
		b.reconciler.doc.Operations[i].NextRun = time.Now().Add(time.Hour)
	}
	calls := 0
	b.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls++
		if r.NodeID != request.NodeIDs[0] {
			t.Error("restart reused prior cursor")
		}
		return autofallbackResult(r, true), nil
	})
	b.runDurableServiceJob(root, time.Now())
	if calls != 1 || durableJobAt(t, b, id).Cursor != 1 {
		t.Fatal("restart did not perform one fresh first check")
	}
}

func TestDurableNodeContinuationYieldsToOriginalStop(t *testing.T) {
	a, first, adapter, cfg := serviceRuntimeFixture(t)
	snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "continuation", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@continuation.example:443?security=tls&sni=continuation.example", time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	second := ""
	for _, node := range snapshot.Nodes {
		if node.ID != first {
			second = node.ID
			break
		}
	}
	if second == "" {
		t.Fatal("second candidate missing")
	}
	initReconcilerFixture(t, a, time.Now())
	a.reconciler.doc.Operations = futureNodeQueueOperations(time.Now())
	if err := a.persistReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	root, cancel := context.WithCancel(context.Background())
	a.StartNodeChecks(root)
	t.Cleanup(func() { cancel(); _ = a.WaitNodeChecks(context.Background()) })
	calls := 0
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls++
		return autofallbackResult(r, true), nil
	})
	id := enqueueNodeFixture(t, a, nodeCheckJobRequest{NodeIDs: []string{first, second}, Mode: "service", ServiceID: "telegram", ExpectedRevision: &cfg.Revision, IdempotencyKey: "continuation-stop-priority"})
	a.reconciler.wake = make(chan struct{}, 1)
	a.runDurableServiceJob(root, time.Now())
	takeContinuationWake(t, a, true)
	stop := durableRuntimeAccept(t, a, "stop", "continuation-original-stop", cfg.Revision)
	a.runDurableServiceJob(root, time.Now())
	if durableJobAt(t, a, stop.ID).State != "completed" || !a.Store.Get().ServiceControl.Stopped || len(adapter.calls) != 2 || calls != 1 || durableJobAt(t, a, id).Cursor != 1 {
		t.Fatal("continuation overtook original Stop", calls, adapter.calls)
	}
}
