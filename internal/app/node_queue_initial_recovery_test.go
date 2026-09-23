package app

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func futureNodeQueueOperations(now time.Time) []automationOperation {
	ops := make([]automationOperation, 0, 5)
	for _, kind := range []string{"node-recovery", "node-fallback", "legacy-routes", "feeds", "service-checks"} {
		ops = append(ops, automationOperation{Kind: kind, State: "completed", NextRun: now.Add(time.Hour)})
	}
	return ops
}

func TestBulkRecoveryDueIncludesMissingPriorityOperations(t *testing.T) {
	now := time.Now()
	for _, missing := range []string{"all", "node-recovery", "node-fallback", "feeds"} {
		t.Run(missing, func(t *testing.T) {
			a := &App{}
			a.reconciler.started = true
			for _, op := range futureNodeQueueOperations(now) {
				if missing != "all" && op.Kind != missing {
					a.reconciler.doc.Operations = append(a.reconciler.doc.Operations, op)
				}
			}
			if !a.bulkRecoveryDue(now) {
				t.Fatalf("missing %s did not reserve initial recovery priority", missing)
			}
			a.reconciler.doc.Operations = futureNodeQueueOperations(now)
			if a.bulkRecoveryDue(now) {
				t.Fatal("completed initial round did not release priority")
			}
		})
	}
	for _, blocked := range []bool{false, true} {
		a := &App{}
		a.reconciler.started = blocked
		a.reconciler.blocked = blocked
		if a.bulkRecoveryDue(now) {
			t.Fatal("inactive or blocked reconciler reserved priority forever")
		}
	}
}

func TestServiceQueuesWaitForInitialReconcilerWithDisabledFeatures(t *testing.T) {
	for _, scope := range []string{"selected", "all-vless"} {
		t.Run(scope, func(t *testing.T) {
			a, ids := newNodeJobTest(t, 1)
			withBulkConfig(t, a)
			if !a.Store.Get().SafeMode || a.Store.Get().ServiceControl.Schedule.Enabled || a.Dataplane != nil {
				t.Fatal("fixture must have disabled routing and scheduled checks")
			}
			a.reconciler.started = true
			a.reconciler.path = a.Store.AutomationStatePath()
			if err := a.loadReconcilerLocked(context.Background()); err != nil {
				t.Fatal(err)
			}
			if scope == "selected" {
				calls := 0
				a.NodeChecker = jobNodeChecker(func(ctx context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
					calls++
					return bulkTestResult(q), nil
				})
				revision := a.Store.Get().Revision
				id := enqueueNodeFixture(t, a, nodeCheckJobRequest{NodeIDs: ids, Mode: "service", ServiceID: "telegram", ExpectedRevision: &revision, IdempotencyKey: "initial-selected-durable"})
				if a.runDurableServiceJob(context.Background(), time.Now()) || calls != 0 {
					t.Fatal("queue overtook initial recovery")
				}
				a.reconcileRound(context.Background(), time.Now())
				if len(a.reconciler.doc.Operations) != 5 || a.bulkRecoveryDue(time.Now()) {
					t.Fatal("disabled operations retained priority")
				}
				a.reconcileRound(context.Background(), time.Now())
				if j := durableJobAt(t, a, id); j.State != "completed" || j.Cursor != 1 || calls != 1 {
					t.Fatal("durable queue did not resume", j)
				}
				return
			}
			waiting, resume := make(chan struct{}), make(chan struct{})
			var once sync.Once
			a.nodeChecks.bulkWait = func(ctx context.Context, _ time.Duration) error {
				once.Do(func() { close(waiting) })
				select {
				case <-resume:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			var calls atomic.Int32
			a.NodeChecker = jobNodeChecker(func(ctx context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				calls.Add(1)
				return bulkTestResult(q), nil
			})
			if scope == "all-vless" {
				if w := postBulkTest(t, a, allBulkRequest(t, a)); w.Code != 202 {
					t.Fatal(w.Code, w.Body.String())
				}
			} else if w := postNodeJob(t, a, ids, "service"); w.Code != 202 {
				t.Fatal(w.Code, w.Body.String())
			}
			select {
			case <-waiting:
			case <-time.After(3 * time.Second):
				t.Fatal("queue overtook the initial recovery round")
			}
			if calls.Load() != 0 {
				t.Fatal("checker ran before initial recovery")
			}
			// Run the real coordinator with disabled features: every operation
			// must still get a future schedule and release the waiting queue.
			a.reconcileRound(context.Background(), time.Now())
			if len(a.reconciler.doc.Operations) != 5 || a.bulkRecoveryDue(time.Now()) {
				t.Fatal("disabled operations left the queue waiting indefinitely")
			}
			close(resume)
			j := joinNodeJob(t, a)
			if j.State != "completed" || j.Completed != 1 || calls.Load() != 1 {
				t.Fatalf("queue did not resume after initial recovery: %+v", j)
			}
		})
	}
}
