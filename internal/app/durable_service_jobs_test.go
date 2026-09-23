package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func durableFixture(t *testing.T) (*App, serviceControlJobRequest) {
	t.Helper()
	a, _ := serviceControlFixture(t, 2)
	initReconcilerFixture(t, a, time.Now())
	revision := a.Store.Get().Revision
	return a, serviceControlJobRequest{Kind: "select", ServiceIDs: []string{"telegram"}, ExpectedRevision: &revision, IdempotencyKey: "request-durable-0001"}
}

func durableJobAt(t *testing.T, a *App, id uint64) durableServiceJob {
	t.Helper()
	a.reconciler.mu.Lock()
	defer a.reconciler.mu.Unlock()
	for _, j := range a.reconciler.doc.Jobs {
		if j.ID == id {
			return j
		}
	}
	t.Fatal("job missing")
	return durableServiceJob{}
}

func TestDurableServiceJobsLostResponseTwoWindowsAndNoSecrets(t *testing.T) {
	a, request := durableFixture(t)
	entered, cleanup, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls.Add(1)
		close(entered)
		<-cleanup
		return autofallbackResult(req, true), nil
	})
	w := controlRequest(a, "POST", "/api/v1/service-control/jobs", request)
	if w.Code != 202 {
		t.Fatalf("accept %d %s", w.Code, w.Body.String())
	}
	var response struct{ Job nodeCheckJob }
	if json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Job.State != "queued" {
		t.Fatal(w.Body.String())
	}
	id := response.Job.ID
	go func() { a.runDurableServiceJob(context.Background(), time.Now()); close(finished) }()
	awaitOperation(t, entered)
	defer func() {
		select {
		case <-finished:
		default:
			close(cleanup)
			<-finished
		}
	}()
	// Both the lost-response retry and another window work while the lease is held.
	for _, key := range []string{request.IdempotencyKey, "request-other-window"} {
		retry := request
		retry.IdempotencyKey = key
		w = controlRequest(a, "POST", "/api/v1/service-control/jobs", retry)
		if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Job.ID != id {
			t.Fatalf("retry %d %s", w.Code, w.Body.String())
		}
	}
	changed := request
	changed.Kind = "check"
	w = controlRequest(a, "POST", "/api/v1/service-control/jobs", changed)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "JOB_KEY_CONFLICT") {
		t.Fatal(w.Code, w.Body.String())
	}
	close(cleanup)
	awaitOperation(t, finished)
	if calls.Load() != 1 || durableJobAt(t, a, id).State != "completed" {
		t.Fatal("duplicate execution or no durable outcome")
	}
	data, err := os.ReadFile(a.Store.AutomationStatePath())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"vless://", "private.example", request.IdempotencyKey, "request-other-window", "recommended_node_id", `"available":true`} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("journal contains %s", secret)
		}
	}
	// Completed alias survives restart and still resolves to the original job.
	b := &App{Store: a.Store}
	b.reconciler.started, b.reconciler.path = true, a.Store.AutomationStatePath()
	if err := b.loadReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = "request-other-window"
	got, err := b.enqueueDurableServiceJob(context.Background(), request)
	if err != nil || got.ID != id || got.State != "completed" {
		t.Fatalf("restart retry: %+v %v", got, err)
	}
}

func TestDurableServiceCancelKeepsAdmissionThroughCleanup(t *testing.T) {
	a, request := durableFixture(t)
	entered, canceled, cleanup, finished := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-cleanup
		return dataplane.NodeCheckResult{}, ctx.Err()
	})
	j, err := a.enqueueDurableServiceJob(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	go func() { a.runDurableServiceJob(context.Background(), time.Now()); close(finished) }()
	awaitOperation(t, entered)
	defer func() {
		select {
		case <-finished:
		default:
			close(cleanup)
			<-finished
		}
	}()
	w := controlRequest(a, "DELETE", fmt.Sprintf("/api/v1/service-control/current?job_id=%d", j.ID+1), nil)
	if w.Code != 409 {
		t.Fatal("old/unknown ID accepted")
	}
	w = controlRequest(a, "DELETE", fmt.Sprintf("/api/v1/service-control/current?job_id=%d", j.ID), nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	awaitOperation(t, canceled)
	if release, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("lease released during cleanup")
	}
	if job := durableJobAt(t, a, j.ID); job.State != "canceling" || !job.CancelRequested {
		t.Fatal(job)
	}
	// Cancellation intent is already on disk, even if power is lost in cleanup.
	data, _ := os.ReadFile(a.Store.AutomationStatePath())
	var doc reconcilerDocument
	if json.Unmarshal(data, &doc) != nil || !doc.Jobs[0].CancelRequested {
		t.Fatal("cancel not durable")
	}
	close(cleanup)
	awaitOperation(t, finished)
	if job := durableJobAt(t, a, j.ID); job.State != "canceled" || job.CleanupOutcome != "joined" {
		t.Fatal(job)
	}
	if a.Operations.Snapshot().Active != 0 {
		t.Fatal("lease leaked")
	}
}

func TestDurableServiceRestartRechecksIntentAndDoesNotRestoreProof(t *testing.T) {
	for _, phase := range []string{"queued", "running", "canceling", "interrupted"} {
		t.Run(phase, func(t *testing.T) {
			a, request := durableFixture(t)
			j, err := a.enqueueDurableServiceJob(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			a.reconciler.doc.Jobs[0].State = phase
			a.reconciler.doc.Jobs[0].Attempts = 1
			a.reconciler.doc.Jobs[0].CancelRequested = phase == "canceling"
			if err := a.persistReconcilerLocked(context.Background()); err != nil {
				t.Fatal(err)
			}
			// Same configured Stores, fresh application/worker lifetime after boot recovery.
			b := &App{Store: a.Store, Nodes: a.Nodes, Catalog: a.Catalog, FreshProfile: a.FreshProfile}
			b.StartNodeChecks(context.Background())
			t.Cleanup(func() { _ = b.WaitNodeChecks(context.Background()) })
			b.reconciler.started, b.reconciler.path = true, a.Store.AutomationStatePath()
			if err := b.loadReconcilerLocked(context.Background()); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			b.NodeChecker = jobNodeChecker(func(ctx context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				calls.Add(1)
				return autofallbackResult(req, true), nil
			})
			b.runDurableServiceJob(context.Background(), time.Now().Add(time.Minute))
			got := durableJobAt(t, b, j.ID)
			if phase == "canceling" {
				if calls.Load() != 0 || got.State != "canceled" {
					t.Fatal("revoked job resumed", got)
				}
			} else if calls.Load() != 1 || got.State != "completed" {
				t.Fatal("fresh check missing", got)
			}
		})
	}
}

func TestDurableServiceChangedSettingsAndStorageFailureRefuseWork(t *testing.T) {
	a, request := durableFixture(t)
	j, err := a.enqueueDurableServiceJob(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Store.SetSafeMode(!a.Store.Get().SafeMode); err != nil {
		t.Fatal(err)
	}
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		t.Fatal("stale job probed")
		return dataplane.NodeCheckResult{}, nil
	})
	a.runDurableServiceJob(context.Background(), time.Now())
	if got := durableJobAt(t, a, j.ID); got.State != "failed" || got.Reason != "settings-changed" {
		t.Fatal(got)
	}
	b, request := durableFixture(t)
	foreign := []byte(`{"different_owner":true}`)
	if err := os.WriteFile(b.Store.AutomationStatePath(), foreign, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.enqueueDurableServiceJob(context.Background(), request); err == nil || !b.reconciler.blocked || len(b.reconciler.doc.Jobs) != 0 {
		t.Fatal("uncertain write accepted")
	}
	data, _ := os.ReadFile(b.Store.AutomationStatePath())
	if string(data) != string(foreign) {
		t.Fatal("foreign journal overwritten")
	}
}

func TestDurableServiceBusyYieldDoesNotSpendAttemptAndQueueIsBounded(t *testing.T) {
	a, request := durableFixture(t)
	j, err := a.enqueueDurableServiceJob(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.runDurableServiceJob(context.Background(), time.Now()) {
		t.Fatal("busy job consumed recovery round")
	}
	release()
	if got := durableJobAt(t, a, j.ID); got.Attempts != 0 || got.State != "queued" {
		t.Fatal(got)
	}
	for i := range 8 {
		request.IdempotencyKey = fmt.Sprintf("window-alias-%016d", i)
		if _, err := a.enqueueDurableServiceJob(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	request.IdempotencyKey = "window-alias-too-many"
	if _, err := a.enqueueDurableServiceJob(context.Background(), request); !errors.Is(err, errDurableQueueFull) {
		t.Fatal("unbounded alias retention", err)
	}
	if validateReconcilerDocument(a.reconciler.doc) != nil {
		t.Fatal("invalid document")
	}
}
