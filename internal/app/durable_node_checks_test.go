package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func durableNodeFixture(t *testing.T, count int) (*App, nodeCheckJobRequest) {
	t.Helper()
	a, ids := serviceControlFixture(t, count)
	initReconcilerFixture(t, a, time.Now())
	a.reconciler.doc.Operations = futureNodeQueueOperations(time.Now())
	for i := range a.reconciler.doc.Operations {
		a.reconciler.doc.Operations[i].ConfigFingerprint = automationConfigFingerprint(a.Store.Get())
		a.reconciler.doc.Operations[i].Reason = "scheduled"
	}
	if err := a.persistReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return autofallbackResult(r, true), nil
	})
	revision := a.Store.Get().Revision
	return a, nodeCheckJobRequest{NodeIDs: ids, Mode: "service", ServiceID: "telegram", ExpectedRevision: &revision, IdempotencyKey: "durable-node-request-001"}
}

func enqueueNodeFixture(t *testing.T, a *App, request nodeCheckJobRequest) uint64 {
	t.Helper()
	w := controlRequest(a, "POST", "/api/v1/node-checks", request)
	var response struct{ Job nodeCheckJob }
	if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Job.ID == 0 {
		t.Fatalf("accept: %d %s", w.Code, w.Body.String())
	}
	return response.Job.ID
}

func TestDurableNodeAdmissionQueuesDuringAnotherOperationWithoutStartingIO(t *testing.T) {
	for _, catalog := range []bool{false, true} {
		t.Run(fmt.Sprint(catalog), func(t *testing.T) {
			a, q := durableNodeFixture(t, 2)
			if catalog {
				q = durableCatalogRequest(t, a)
			}
			var calls atomic.Int32
			a.NodeChecker = jobNodeChecker(func(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				calls.Add(1)
				return autofallbackResult(request, true), nil
			})
			release, err := a.Operations.Exclusive(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			id := enqueueNodeFixture(t, a, q)
			a.runDurableServiceJob(context.Background(), time.Now())
			if j := durableJobAt(t, a, id); j.State != "queued" || j.Cursor != 0 || j.Attempts != 0 || calls.Load() != 0 {
				t.Fatal("queue crossed another owner's lease", j)
			}
			release()
			a.runDurableServiceJob(context.Background(), time.Now().Add(6*time.Second))
			if j := durableJobAt(t, a, id); j.Cursor != 1 || calls.Load() != 1 {
				t.Fatal("queued check did not resume", j)
			}
		})
	}
}

func TestDurableNodeQueuedAdmissionDoesNotAuthorizeChangedSettingsOrFencedRecovery(t *testing.T) {
	a, q := durableNodeFixture(t, 1)
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	id := enqueueNodeFixture(t, a, q)
	if err := a.Store.SetSafeMode(!a.Store.Get().SafeMode); err != nil {
		t.Fatal(err)
	}
	release()
	a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		t.Error("stale queued intent reached network")
		return dataplane.NodeCheckResult{}, nil
	})
	a.runDurableServiceJob(context.Background(), time.Now())
	if j := durableJobAt(t, a, id); j.State != "failed" || j.Reason != "settings-changed" {
		t.Fatal(j)
	}
	a.Operations.Fence()
	q.IdempotencyKey = "fenced-new-node-job"
	revision := a.Store.Get().Revision
	q.ExpectedRevision = &revision
	w := controlRequest(a, "POST", "/api/v1/node-checks", q)
	if w.Code == 202 || len(a.reconciler.doc.Jobs) != 1 {
		t.Fatal("recovery fence admitted new work", w.Code)
	}
}

func TestDurableNodeBatchYieldsRetainsIdentityAndNoSecrets(t *testing.T) {
	a, request := durableNodeFixture(t, 2)
	before := a.Store.Get()
	id := enqueueNodeFixture(t, a, request)
	a.runDurableServiceJob(context.Background(), time.Now())
	j := durableJobAt(t, a, id)
	if j.State != "queued" || j.Cursor != 1 || j.Attempts != 0 || j.CheckNetwork == "" {
		t.Fatal("did not yield after one node", j)
	}
	if a.Operations.Snapshot().Active != 0 {
		t.Fatal("admission held between checks")
	}
	if retry := enqueueNodeFixture(t, a, request); retry != id {
		t.Fatal("lost response created duplicate")
	}
	request.IdempotencyKey = "other-window-node-request"
	if retry := enqueueNodeFixture(t, a, request); retry != id {
		t.Fatal("two windows duplicated intent")
	}
	a.runDurableServiceJob(context.Background(), time.Now().Add(2*time.Second))
	j = durableJobAt(t, a, id)
	p := a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if j.State != "completed" || j.Cursor != 2 || p.State != "completed" || p.Completed != 2 || len(p.Results) != 2 || p.Passed != 2 {
		t.Fatal("completion hidden or result lost", j, p)
	}
	if !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("check mutated routing intent")
	}
	data, err := os.ReadFile(a.Store.AutomationStatePath())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"vless://", "node0.example", "123e4567", request.IdempotencyKey, `"available":true`, `"results"`} {
		if strings.Contains(string(data), secret) {
			t.Fatal("private data or replayable proof in journal", secret)
		}
	}
	changed := request
	changed.Mode = "tcp"
	w := controlRequest(a, "POST", "/api/v1/node-checks", changed)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "JOB_KEY_CONFLICT") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestDurableNodeRestartFreshChecksAndCanceledIntent(t *testing.T) {
	for _, state := range []string{"queued", "running", "canceling", "completed"} {
		t.Run(state, func(t *testing.T) {
			a, request := durableNodeFixture(t, 2)
			id := enqueueNodeFixture(t, a, request)
			a.runDurableServiceJob(context.Background(), time.Now())
			j := &a.reconciler.doc.Jobs[0]
			j.State, j.CancelRequested = state, state == "canceling"
			if state == "completed" {
				j.Cursor = 2
			}
			if err := a.persistReconcilerLocked(context.Background()); err != nil {
				t.Fatal(err)
			}
			b := &App{Store: a.Store, Nodes: a.Nodes, Catalog: a.Catalog, FreshProfile: a.FreshProfile}
			b.StartNodeChecks(context.Background())
			t.Cleanup(func() { _ = b.WaitNodeChecks(context.Background()) })
			b.reconciler.started, b.reconciler.path = true, a.Store.AutomationStatePath()
			if err := b.loadReconcilerLocked(context.Background()); err != nil {
				t.Fatal(err)
			}
			// The separate initial-recovery test exercises the real coordinator.
			// Here model its completed boot reconciliation before dispatch.
			for i := range b.reconciler.doc.Operations {
				b.reconciler.doc.Operations[i].NextRun = time.Now().Add(time.Hour)
			}
			p := b.nodeCheckCurrentView()["job"].(*nodeCheckJob)
			if p.ID != id || len(p.Results) != 0 || p.Passed != 0 {
				t.Fatal("restart invented current proof", p)
			}
			calls := 0
			b.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				calls++
				if r.NodeID != request.NodeIDs[0] {
					t.Error("old cursor resumed instead of fresh pass")
				}
				return autofallbackResult(r, true), nil
			})
			b.runDurableServiceJob(context.Background(), time.Now().Add(time.Minute))
			want := 1
			if state == "completed" || state == "canceling" {
				want = 0
			}
			if calls != want {
				t.Fatal("wrong restart behavior", calls, durableJobAt(t, b, id))
			}
			if state == "completed" && enqueueNodeFixture(t, b, request) != id {
				t.Fatal("completed retry replayed")
			}
		})
	}
}

func TestDurableNodeCancelWaitsForCleanupAndOldIDCannotCancelNew(t *testing.T) {
	a, request := durableNodeFixture(t, 2)
	entered, canceled, cleanup, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-cleanup
		return dataplane.NodeCheckResult{}, ctx.Err()
	})
	id := enqueueNodeFixture(t, a, request)
	go func() { a.runDurableServiceJob(context.Background(), time.Now()); close(done) }()
	awaitOperation(t, entered)
	defer func() {
		select {
		case <-done:
		default:
			close(cleanup)
			<-done
		}
	}()
	if retry := enqueueNodeFixture(t, a, request); retry != id {
		t.Fatal("retry blocked behind lease")
	}
	w := controlRequest(a, "DELETE", fmt.Sprintf("/api/v1/node-checks/current?job_id=%d", id+1), nil)
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = controlRequest(a, "DELETE", fmt.Sprintf("/api/v1/node-checks/current?job_id=%d", id), nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	awaitOperation(t, canceled)
	if release, e := a.Operations.Exclusive(context.Background()); !errors.Is(e, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("cleanup released too early", e)
	}
	close(cleanup)
	awaitOperation(t, done)
	if j := durableJobAt(t, a, id); j.State != "canceled" || j.Cursor != 0 {
		t.Fatal(j)
	}
	request.IdempotencyKey = "new-node-check-request"
	newID := enqueueNodeFixture(t, a, request)
	w = controlRequest(a, "DELETE", fmt.Sprintf("/api/v1/node-checks/current?job_id=%d", id), nil)
	if w.Code != 200 || durableJobAt(t, a, newID).CancelRequested {
		t.Fatal("old cancel affected new request")
	}
}

func TestDurableNodeChangesAndFailedCleanupStopBatch(t *testing.T) {
	for _, mode := range []string{"network", "definition", "config", "cleanup", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			a, request := durableNodeFixture(t, 2)
			id := enqueueNodeFixture(t, a, request)
			var calls atomic.Int32
			root, stop := context.WithCancel(context.Background())
			defer stop()
			a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				calls.Add(1)
				if mode == "cleanup" {
					return dataplane.NodeCheckResult{ErrorCode: "node-cleanup-failed"}, errors.New("failed")
				}
				if mode == "shutdown" {
					stop()
					return dataplane.NodeCheckResult{}, ctx.Err()
				}
				return autofallbackResult(r, true), nil
			})
			a.runDurableServiceJob(root, time.Now())
			switch mode {
			case "network":
				a.FreshProfile = func(context.Context) (string, error) { return "wan-new", nil }
			case "definition":
				a.Catalog.Services[0].ProbeURL = "https://changed.example/"
			case "config":
				if e := a.Store.SetSafeMode(!a.Store.Get().SafeMode); e != nil {
					t.Fatal(e)
				}
			}
			if mode != "shutdown" {
				a.runDurableServiceJob(context.Background(), time.Now().Add(2*time.Second))
			}
			j := durableJobAt(t, a, id)
			if calls.Load() != 1 {
				t.Fatal("continued after changed context or failure", calls.Load(), j)
			}
			if mode == "shutdown" {
				if j.State != "interrupted" {
					t.Fatal(j)
				}
			} else if j.State != "failed" {
				t.Fatal(j)
			}
			if mode == "cleanup" && (!a.Operations.Snapshot().Fenced || j.CleanupOutcome != "unverified") {
				t.Fatal("cleanup failure not fenced", j)
			}
			if mode == "network" {
				if j.Reason != "network-unconfirmed" || !strings.Contains(j.presentation().Message, "сети") {
					t.Fatal("network failure lost its explanation", j)
				}
				raw, e := os.ReadFile(a.Store.AutomationStatePath())
				if e != nil {
					t.Fatal(e)
				}
				var saved reconcilerDocument
				if json.Unmarshal(raw, &saved) != nil || validateDurableServiceJobs(saved.Jobs) != nil {
					t.Fatal("reason does not survive journal read")
				}
			}
		})
	}
}

func TestDurableNodeTCPDoesNotProduceRouteProof(t *testing.T) {
	a, request := durableNodeFixture(t, 1)
	request.Mode = "tcp"
	request.ServiceID = ""
	a.NodePinger = testNodePinger(func(context.Context, []byte) dataplane.NodePingResult {
		return dataplane.NodePingResult{Reachable: true, LatencyMS: 42}
	})
	before, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	id := enqueueNodeFixture(t, a, request)
	a.runDurableServiceJob(context.Background(), time.Now())
	view := a.nodeCheckCurrentView()
	p := view["job"].(*nodeCheckJob)
	after, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	if p.State != "completed" || p.ID != id || len(p.Results) != 1 || p.Results[0].Available || !p.Results[0].Reachable || p.Passed != 0 || !reflect.DeepEqual(before, after) {
		t.Fatal("TCP became proof", p)
	}
	if len(view["pings"].([]nodeCheckItem)) != 1 {
		t.Fatal("ping not visible")
	}
}

func TestDurableNodeFailedJournalNeverAcknowledgesCompletion(t *testing.T) {
	a, request := durableNodeFixture(t, 2)
	id := enqueueNodeFixture(t, a, request)
	original := a.reconciler.path
	// Simulate a disappeared/unwritable state directory after the checker
	// completed, while leaving the previous durable journal intact.
	badParent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(badParent, []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		a.reconciler.mu.Lock()
		a.reconciler.path = filepath.Join(badParent, "journal.json")
		a.reconciler.mu.Unlock()
		return autofallbackResult(r, true), nil
	})
	a.runDurableServiceJob(context.Background(), time.Now())
	view := a.nodeCheckCurrentView()
	p := view["job"].(*nodeCheckJob)
	if view["queue_blocked"] != true || p.State != "failed" || p.ErrorCode != "JOB_STORAGE_UNAVAILABLE" || p.ID != id {
		t.Fatal("unsaved completion acknowledged", view)
	}
	if a.runDurableServiceJob(context.Background(), time.Now().Add(time.Minute)) {
		t.Fatal("queue continued after journal failure")
	}
	data, err := os.ReadFile(original)
	if err != nil {
		t.Fatal(err)
	}
	var doc reconcilerDocument
	if json.Unmarshal(data, &doc) != nil || doc.Jobs[0].State != "running" || doc.Jobs[0].Cursor != 0 {
		t.Fatal("last saved journal overwritten")
	}
	if a.Operations.Snapshot().Active != 0 {
		t.Fatal("clean checker retained lease")
	}
}

func TestDurableNodeQueueByteLimitPreservesStopAndExistingJobs(t *testing.T) {
	a, request := durableNodeFixture(t, 64)
	accepted := 0
	for i := 0; i < maxDurableServiceJobs; i++ {
		request.IdempotencyKey = fmt.Sprintf("capacity-node-check-%04d", i)
		w := controlRequest(a, "POST", "/api/v1/node-checks", request)
		if w.Code == 429 {
			if !strings.Contains(w.Body.String(), "JOB_QUEUE_FULL") || a.reconciler.blocked {
				t.Fatal("normal queue capacity blocked recovery", w.Body.String())
			}
			break
		}
		if w.Code != 202 {
			t.Fatal(w.Code, w.Body.String())
		}
		accepted++
		j := &a.reconciler.doc.Jobs[len(a.reconciler.doc.Jobs)-1]
		finishDurableJob(j, "completed", "", time.Now())
		if err := a.persistReconcilerLocked(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if accepted == 0 || accepted >= maxDurableServiceJobs-1 {
		t.Fatal("byte bound was not exercised", accepted)
	}
	stop, err := a.enqueueDurableServiceJob(context.Background(), serviceControlJobRequest{Kind: "stop", ExpectedRevision: request.ExpectedRevision, IdempotencyKey: "stop-after-node-queue-full"})
	if err != nil || stop.State != "queued" || a.reconciler.blocked {
		t.Fatal("no reserved Stop admission", err, stop)
	}
	data, err := os.ReadFile(a.Store.AutomationStatePath())
	if err != nil || len(data) >= maxReconcilerBytes {
		t.Fatal("journal exceeded limit", len(data), err)
	}
	if len(a.reconciler.doc.Jobs) != accepted+1 {
		t.Fatal("existing identities evicted")
	}
}
