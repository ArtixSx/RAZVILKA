package app

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestDurableJobPreDispatchAdmissionRetryActuallyDispatchesAcceptedJob(t *testing.T) {
	for _, kind := range []string{"select", "stop"} {
		for _, state := range []string{"queued", "interrupted"} {
			t.Run(kind+"/"+state, func(t *testing.T) {
				var a *App
				var accepted durableServiceJob
				var completedEffect func() bool
				var calls atomic.Int32
				if kind == "stop" {
					var adapter *serviceRuntimeAdapter
					a, _, adapter, _ = serviceRuntimeFixture(t)
					cfgRevision := a.Store.Get().Revision
					initReconcilerFixture(t, a, time.Now())
					accepted = durableRuntimeAccept(t, a, "stop", "admission-stop-request", cfgRevision)
					completedEffect = func() bool { return a.Store.Get().ServiceControl.Stopped && len(adapter.calls) == 2 }
				} else {
					var request serviceControlJobRequest
					a, request = durableFixture(t)
					var err error
					accepted, err = a.enqueueDurableServiceJob(context.Background(), request)
					if err != nil {
						t.Fatal(err)
					}
					a.NodeChecker = jobNodeChecker(func(ctx context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
						calls.Add(1)
						return autofallbackResult(req, true), nil
					})
					completedEffect = func() bool { return calls.Load() == 1 }
				}
				// Resume an already bounded attempt without spending another retry
				// merely because the scheduler cannot acquire its writer lease.
				if state == "interrupted" {
					a.reconciler.doc.Jobs[0].State = state
					a.reconciler.doc.Jobs[0].Attempts = 1
					if err := a.persistReconcilerLocked(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				before := durableJobAt(t, a, accepted.ID)
				w := holdReconcilerWriter(t, a)
				if !a.runDurableServiceJob(context.Background(), time.Now()) || !a.reconciler.blocked || !a.reconciler.retryAdmission || a.reconciler.activeJobID != 0 || a.reconciler.cancel != nil || calls.Load() != 0 {
					t.Fatal("pre-dispatch refusal did not retain the writer fence")
				}
				if got := durableJobAt(t, a, accepted.ID); !reflect.DeepEqual(got, before) {
					t.Fatalf("unstarted job lost its selectable state or spent a retry: state=%s attempts=%d", got.State, got.Attempts)
				}
				if completedEffect() {
					t.Fatal("worker ran without durable dispatch admission")
				}
				_ = w.Close()
				a.reconcileRound(context.Background(), time.Now())
				got := durableJobAt(t, a, accepted.ID)
				if a.reconciler.blocked || got.State != "completed" || got.Attempts != before.Attempts+1 || !completedEffect() {
					t.Fatalf("accepted job stranded after lease recovery: state=%s attempts=%d blocked=%v", got.State, got.Attempts, a.reconciler.blocked)
				}
			})
		}
	}
}

func TestDurableJobCompletionAdmissionRetryNeverReplaysCompletedWorker(t *testing.T) {
	a, request := durableFixture(t)
	accepted, err := a.enqueueDurableServiceJob(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var w *restorejournal.FileTarget
	var holdErr error
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls.Add(1)
		w, holdErr = restorejournal.OpenFileTarget(a.reconciler.path)
		return autofallbackResult(req, true), holdErr
	})
	a.runDurableServiceJob(context.Background(), time.Now())
	if holdErr != nil {
		t.Fatal(holdErr)
	}
	if w == nil {
		t.Fatal("worker never dispatched")
	}
	defer w.Close()
	completed := durableJobAt(t, a, accepted.ID)
	if !a.reconciler.blocked || !a.reconciler.retryAdmission || completed.State != "completed" || completed.Attempts != 1 || calls.Load() != 1 {
		t.Fatal("completion checkpoint was not retained after acquisition refusal")
	}
	_ = w.Close()
	// Retry metadata through the normal scheduler. Keep all maintenance in the
	// future so the only eligible work is the already completed accepted job.
	for _, kind := range []string{"node-fallback", "service-checks"} {
		a.reconciler.doc.Operations = append(a.reconciler.doc.Operations, automationOperation{Kind: kind, State: "completed", Reason: "scheduled", ConfigFingerprint: automationConfigFingerprint(a.Store.Get())})
	}
	for i := range a.reconciler.doc.Operations {
		a.reconciler.doc.Operations[i].NextRun = time.Now().Add(time.Hour)
	}
	a.reconcileRound(context.Background(), time.Now())
	got := durableJobAt(t, a, accepted.ID)
	if a.reconciler.blocked || !reflect.DeepEqual(got, completed) || calls.Load() != 1 {
		t.Fatal("completion metadata retry replayed worker or lost its outcome")
	}
	data, err := os.ReadFile(a.reconciler.path)
	var saved reconcilerDocument
	if err != nil || json.Unmarshal(data, &saved) != nil || len(saved.Jobs) != 1 || saved.Jobs[0].State != "completed" || saved.Jobs[0].Attempts != completed.Attempts {
		t.Fatal("completion was not durably saved", err)
	}
}
