package app

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func TestSelectedNodeQueueYieldsAfterCleanupAndStopsOnNetworkChange(t *testing.T) {
	a, ids := newNodeJobTest(t, 2)
	yielded, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var changed atomic.Bool
	var calls atomic.Int32
	a.FreshProfile = func(context.Context) (string, error) {
		if changed.Load() {
			return "wan-abcdef012345", nil
		}
		return "wan-0123456789ab", nil
	}
	a.nodeChecks.bulkWait = func(ctx context.Context, _ time.Duration) error {
		once.Do(func() { close(yielded) })
		select {
		case <-resume:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls.Add(1)
		return bulkTestResult(q), nil
	})
	if w := postNodeJob(t, a, ids, "service"); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	select {
	case <-yielded:
	case <-time.After(3 * time.Second):
		t.Fatal("selected batch never yielded after its first cleanup")
	}
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal("selected batch blocked recovery between nodes", err)
	}
	changed.Store(true)
	release()
	close(resume)
	j := joinNodeJob(t, a)
	if j.State != "failed" || j.ErrorCode != "BULK_NETWORK_CHANGED" || j.Completed != 1 || calls.Load() != 1 {
		t.Fatalf("queue continued across changed network: %+v, calls=%d", j, calls.Load())
	}
}

func TestSelectedNodeQueueChecksNonVLESSAndYieldsToRecovery(t *testing.T) {
	a, _ := newNodeJobTest(t, 1)
	s, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "extra", Kind: "manual"}, "ss://YWVzLTEyOC1nY206dGVzdC1wYXNzd29yZA@edge.example:8388", time.Now(), time.Hour, false)
	if err != nil || len(s.Nodes) != 2 {
		t.Fatal("import", err)
	}
	nonVLESS := ""
	for _, node := range s.Nodes {
		if node.Protocol != "vless" {
			nonVLESS = node.ID
		}
	}
	if nonVLESS == "" {
		t.Fatal("missing non-VLESS fixture")
	}
	withBulkConfig(t, a)
	initReconcilerFixture(t, a, time.Now())
	a.reconciler.doc.Operations = futureNodeQueueOperations(time.Now())
	a.reconciler.doc.Operations[0] = automationOperation{Kind: "node-recovery", State: "backoff", NextRun: time.Now().Add(-time.Minute)}
	calls := 0
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls++
		return bulkTestResult(q), nil
	})
	revision := a.Store.Get().Revision
	id := enqueueNodeFixture(t, a, nodeCheckJobRequest{NodeIDs: []string{nonVLESS}, Mode: "service", ServiceID: "telegram", ExpectedRevision: &revision, IdempotencyKey: "non-vless-selected-durable"})
	if a.runDurableServiceJob(context.Background(), time.Now()) || calls != 0 {
		t.Fatal("selected node overtook due recovery")
	}
	a.reconciler.doc.Operations[0].NextRun = time.Now().Add(time.Minute)
	a.runDurableServiceJob(context.Background(), time.Now())
	j := a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if j.ID != id || j.State != "completed" || j.Completed != 1 || j.Skipped != 0 || calls != 1 {
		t.Fatalf("selected non-VLESS skipped: %+v", j)
	}
}
func TestServiceQueuesStopAfterUnrecordedCleanupFailure(t *testing.T) {
	for _, all := range []bool{false, true} {
		t.Run(map[bool]string{false: "selected", true: "all-vless"}[all], func(t *testing.T) {
			a, ids := newNodeJobTest(t, 2)
			a.nodeChecks.bulkWait = bulkTestWait
			var calls atomic.Int32
			a.NodeChecker = jobNodeChecker(func(ctx context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				calls.Add(1)
				result := bulkTestResult(q)
				result.ErrorCode = "node-cleanup-failed"
				return result, errors.New("failed to record result after cleanup failure")
			})
			if all {
				if w := postBulkTest(t, a, allBulkRequest(t, a)); w.Code != 202 {
					t.Fatal(w.Code, w.Body.String())
				}
			} else if w := postNodeJob(t, a, ids, "service"); w.Code != 202 {
				t.Fatal(w.Code, w.Body.String())
			}
			j := joinNodeJob(t, a)
			if j.State != "failed" || j.ErrorCode != "BULK_CLEANUP_REQUIRED" || j.Completed != 1 || calls.Load() != 1 || j.Results[0].Available {
				t.Fatalf("fatal cleanup ignored: %+v calls=%d", j, calls.Load())
			}
		})
	}
}
