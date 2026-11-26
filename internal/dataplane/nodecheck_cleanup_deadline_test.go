package dataplane

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"

	"github.com/ArtixSx/razvilka/internal/evidence"
)

// The cleanup owner can finish filesystem work after its deadline, even if
// its last operation returned nil. That is not a timely cleanup receipt.
func TestExactNodeCleanupDeadlineRevokesSuccessAndFencesNextCheck(t *testing.T) {
	for _, mode := range []string{"service", "connectivity"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := fakeExactNodeChecker(t)
				c.connectivityProbe = func(context.Context, string) (int, error) { return 204, nil }
				calls := 0
				c.cleanup = func(ctx context.Context, _ exactNodeSession) error {
					calls++
					<-ctx.Done()
					return nil
				}
				q := checkedNodeRequest()
				if mode == "service" {
					r, err := c.Check(context.Background(), q)
					if err != nil || r.Available || r.Verdict == evidence.VerdictPass || r.CleanupStatus != NodeCleanupFailed || r.Stage != "cleanup" || r.ErrorCode != "node-cleanup-failed" {
						t.Fatalf("late cleanup retained service success: result=%+v err=%v", r, err)
					}
				} else {
					r, err := c.CheckConnectivity(context.Background(), NodeConnectivityRequest{NodeID: q.NodeID, Outbound: q.Outbound, NetworkProfile: q.NetworkProfile})
					if err != nil || r.Ready || r.CleanupVerified || r.Verdict == evidence.VerdictPass || r.Stage != "cleanup" || r.ErrorCode != "node-cleanup-failed" {
						t.Fatalf("late cleanup retained HTTPS readiness: result=%+v err=%v", r, err)
					}
				}
				if calls != 1 || !c.poisoned.Load() {
					t.Fatal("late cleanup did not retain the runtime fence", calls)
				}
				if _, err := c.Check(context.Background(), q); !errors.Is(err, ErrExactNodeUnavailable) {
					t.Fatal("next check entered an unverified runtime", err)
				}
			})
		})
	}
}

func TestExactNodeRecoveryCancellationCannotClearCleanupFence(t *testing.T) {
	for _, mode := range []string{"before", "during"} {
		t.Run(mode, func(t *testing.T) {
			c := fakeExactNodeChecker(t)
			c.poisoned.Store(true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "before" {
				cancel()
			}
			calls := 0
			c.cleanup = func(context.Context, exactNodeSession) error {
				calls++
				cancel()
				return nil
			}
			if err := c.Recover(ctx); !errors.Is(err, context.Canceled) || !c.poisoned.Load() {
				t.Fatal("canceled recovery cleared an unverified runtime", err, c.poisoned.Load())
			}
			want := 1
			if mode == "before" {
				want = 0
			}
			if calls != want || len(c.gate) != c.Capacity() {
				t.Fatal("canceled recovery continued cleanup or leaked a slot", calls, len(c.gate))
			}
			c.cleanup = func(context.Context, exactNodeSession) error { return nil }
			if err := c.Recover(context.Background()); err != nil || c.poisoned.Load() {
				t.Fatal("a fresh completed recovery could not clear the fence", err)
			}
		})
	}
}
