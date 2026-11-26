package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Models the forward admission boundary used by the autonomy resource guard.
// WithoutCancel on its caller cannot revive this original exclusive owner.
func rollbackForwardOwner(t *testing.T) (context.Context, context.CancelFunc, func(context.Context) error) {
	t.Helper()
	worker, cancel := context.WithCancel(firstStartContext(t))
	t.Cleanup(cancel)
	gate := &operationgate.Gate{}
	owned, release, err := gate.ExclusiveContext(worker)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	guard := func(ctx context.Context) error { return gate.WithExclusiveContext(ctx, func() error { return nil }) }
	return WithReviewGuard(owned, guard), cancel, guard
}

type rollbackForwardGuardAdapter struct {
	*fakeAdapter
	cancelForward context.CancelFunc
	guard         func(context.Context) error
	t             *testing.T
	restored      bool
}

func (a *rollbackForwardGuardAdapter) Health(context.Context, Plan, string) error {
	return errors.New("modeled TLS health failure")
}

func (a *rollbackForwardGuardAdapter) Rollback(ctx context.Context, _ Plan, _ string) error {
	// Foreground intent arrives after health has failed, at rollback entry.
	a.cancelForward()
	if !errors.Is(a.guard(ctx), context.Canceled) {
		a.t.Fatal("the original forward owner was not revoked")
	}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) <= 0 || time.Until(deadline) > defaultRollbackTimeout {
		a.t.Fatal("rollback lost its independent finite budget")
	}
	if err := checkFirstStartReviewGuard(ctx); err != nil {
		return err
	}
	// Shadowing the rejected forward guard must never suppress cancellation
	// of the actual cleanup operation itself.
	cleanup, cancel := context.WithCancel(ctx)
	cancel()
	if !errors.Is(checkFirstStartReviewGuard(cleanup), context.Canceled) {
		a.t.Fatal("cleanup cancellation was ignored")
	}
	a.restored = true
	return nil
}

func (a *rollbackForwardGuardAdapter) VerifyRollback(ctx context.Context, _ Plan, _ string) (bool, error) {
	return a.restored && ctx.Err() == nil, ctx.Err()
}

func TestNFQWS2RollbackContextKeepsOtherAdapterReviewAuthority(t *testing.T) {
	ctx, cancel, guard := rollbackForwardOwner(t)
	m := New(filepath.Join(t.TempDir(), "dataplane"))
	a := &rollbackForwardGuardAdapter{fakeAdapter: &fakeAdapter{id: "nfqws2"}, cancelForward: cancel, guard: guard, t: t}
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	execution, err := m.Apply(ctx, readyNFQWS2Plan(t), nil)
	if !errors.Is(err, context.Canceled) || execution.State != "rollback-failed" || execution.RollbackVerified || a.restored {
		t.Fatal("NFQ-specific cleanup substituted another adapter's authority", execution.State, execution.RollbackVerified, err)
	}
}

func TestNFQWS2FirstStartForwardGuardStillRefusesBeforeRuntime(t *testing.T) {
	refused := errors.New("forward authority revoked")
	ctx := WithReviewGuard(firstStartContext(t), func(context.Context) error { return refused })
	adapter := &NFQWS2Adapter{Runner: nfqws2RunFunc(func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("rejected forward authority reached a runtime command")
		return nil, nil
	})}
	if err := adapter.startFirstStart(ctx, "unused"); !errors.Is(err, refused) {
		t.Fatal("forward first-start authority was bypassed", err)
	}
}

// Uses the actual NFQ adapter, Manager, exact file/lease/native review and
// strict rollback verifier. Only the established process/kernel leaves are
// modeled inside an isolated /opt; this is not packet or child-Wait evidence.
func TestNFQWS2FirstStartRollbackAfterForwardOwnerCancellation(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, which := range []string{"restore", "cleanup-expired", "identity-drift"} {
		t.Run(which, func(t *testing.T) {
			f := newFirstStartFixture(t)
			f.apply(t)
			prior, err := f.a.readLease()
			if err != nil || prior == nil {
				t.Fatal("prior running lease missing", err)
			}
			priorConfig := readText(t, f.a.ConfigPath)
			ctx, cancel, guard := rollbackForwardOwner(t)
			f.plan.PlanID, f.plan.Digest = "dp-forward-cancel", strings.Repeat("b", 64)
			f.plan.Routes[0].Domains = []string{"failed.example"}
			healthFailed, interrupted := false, false
			f.a.HealthProbe = func(context.Context, string) error {
				healthFailed = true
				if which == "cleanup-expired" {
					f.m.RollbackTimeout = time.Nanosecond
					cancel()
				}
				return errors.New("modeled TLS health failure")
			}
			read := f.a.firstStartProcessRead
			f.a.firstStartProcessRead = func(pid int) (components.NFQWSRuntimeProcessIdentity, error) {
				if healthFailed && !interrupted {
					interrupted = true
					cancel()
					if which == "identity-drift" {
						f.identity.Start += "-foreign"
					}
				}
				return read(pid)
			}
			execution, err := f.m.Apply(ctx, f.plan, nil)
			if !healthFailed || err == nil || !errors.Is(guard(context.WithoutCancel(ctx)), context.Canceled) {
				t.Fatal("test did not revoke the original worker after health failure", err)
			}
			if which != "restore" {
				if execution.State != "rollback-failed" || execution.RollbackVerified {
					t.Fatal("cleanup expiry or identity drift lost its strict fence", execution.State, err)
				}
				f.assertWriterReleased(t)
				return
			}
			lease, readErr := f.a.readLease()
			if !interrupted || execution.State != "rolled-back" || !execution.RollbackVerified || readErr != nil || lease == nil || !nfqws2RollbackLeaseEqual(lease, prior) ||
				lease.FirstStart.Phase != nfqws2FirstRunning || lease.FirstStart.Process == nil || *lease.FirstStart.Process == *prior.FirstStart.Process ||
				*lease.FirstStart.Process != f.identity || !f.running || !f.ownedRules || readText(t, f.a.ConfigPath) != priorConfig {
				t.Fatal("exact prior runtime was not restored with a fresh process receipt", execution.State, execution.RollbackVerified, err, readErr)
			}
			f.assertWriterReleased(t)
		})
	}
}
