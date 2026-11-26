package app

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestServiceQueuesPreserveCleanupFailureAfterCancelOrNetworkChange(t *testing.T) {
	for _, scope := range []string{"selected", "all-vless"} {
		for _, cause := range []string{"cancel", "network-change"} {
			t.Run(scope+"/"+cause, func(t *testing.T) {
				a, ids := newNodeJobTest(t, 2)
				a.nodeChecks.bulkWait = bulkTestWait
				var changed atomic.Bool
				var calls atomic.Int32
				a.FreshProfile = func(context.Context) (string, error) {
					if changed.Load() {
						return "wan-abcdef012345", nil
					}
					return "wan-0123456789ab", nil
				}
				a.NodeChecker = jobNodeChecker(func(ctx context.Context, q dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
					calls.Add(1)
					if cause == "cancel" {
						a.nodeChecks.mu.Lock()
						cancel := a.nodeChecks.cancel
						a.nodeChecks.mu.Unlock()
						cancel()
					} else {
						changed.Store(true)
					}
					// Even if a probe produced PASS before cancellation or WAN change,
					// a failed cleanup must remain the actionable terminal result.
					result := bulkTestResult(q)
					result.ErrorCode = "node-cleanup-failed"
					return result, ctx.Err()
				})
				if scope == "all-vless" {
					if w := postBulkTest(t, a, allBulkRequest(t, a)); w.Code != 202 {
						t.Fatal(w.Code, w.Body.String())
					}
				} else if w := postNodeJob(t, a, ids, "service"); w.Code != 202 {
					t.Fatal(w.Code, w.Body.String())
				}
				j := joinNodeJob(t, a)
				if j.State != "failed" || j.ErrorCode != "BULK_CLEANUP_REQUIRED" || j.Completed != 1 || len(j.Results) != 1 || calls.Load() != 1 {
					t.Fatalf("cleanup failure was masked by %s: %+v, calls=%d", cause, j, calls.Load())
				}
				item := j.Results[0]
				if item.ErrorCode != "node-cleanup-failed" || item.Available || item.Verdict != "INCONCLUSIVE" || j.Passed != 0 {
					t.Fatalf("unsafe cleanup result: %+v", item)
				}
				if release, err := a.Operations.Exclusive(context.Background()); err != nil {
					t.Fatal("admission leaked after cleanup returned", err)
				} else {
					release()
				}
			})
		}
	}
}
