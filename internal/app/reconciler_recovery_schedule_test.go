package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func initRecoveryScheduleFixture(t *testing.T, a *App, now time.Time) {
	t.Helper()
	r := &a.reconciler
	r.started = true
	r.path = a.Store.AutomationStatePath()
	if err := a.loadReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"node-recovery", "node-fallback", "legacy-routes", "feeds", "service-checks"} {
		op := automationOperation{Kind: kind, State: "completed", Reason: "scheduled", ConfigFingerprint: automationConfigFingerprint(a.Store.Get()), NextRun: now.Add(time.Hour)}
		if kind == "node-recovery" {
			op.NextRun = now
		}
		r.doc.Operations = append(r.doc.Operations, op)
	}
	if err := a.persistReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func recoveryScheduleOperation(t *testing.T, a *App) automationOperation {
	t.Helper()
	a.reconciler.mu.Lock()
	defer a.reconciler.mu.Unlock()
	for _, op := range a.reconciler.doc.Operations {
		if op.Kind == "node-recovery" {
			return op
		}
	}
	t.Fatal("missing recovery schedule")
	return automationOperation{}
}

func TestReconcilerStaleForwardingDoesNotCompoundRecoveryBackoff(t *testing.T) {
	a, _, adapter, checker, previous := nodeRecoveryFixture(t)
	now := time.Now()
	initRecoveryScheduleFixture(t, a, now)
	checker.fail = true
	before := a.Store.Get()
	if err := a.restoreForwardingRound(context.Background()); !errors.Is(err, dataplane.ErrNetworkChanged) {
		t.Fatalf("fixture did not exercise a stale forwarding proof: %v", err)
	}
	// The coordinator keeps observing every 30 seconds, but the exact checker
	// retains its own one-minute/four-minute delays and three-attempt limit.
	for _, step := range []struct {
		after  time.Duration
		checks int
	}{
		{0, 1}, {30 * time.Second, 1}, {time.Minute, 2},
		{90 * time.Second, 2}, {2 * time.Minute, 2}, {4 * time.Minute, 2},
		{5 * time.Minute, 3}, {6 * time.Minute, 3},
	} {
		a.reconcileRound(context.Background(), now.Add(step.after))
		op := recoveryScheduleOperation(t, a)
		if op.State != "completed" || op.Attempts != 0 || !op.NextRun.Equal(now.Add(step.after+30*time.Second)) {
			t.Fatalf("stale forwarding compounded retry delay after %v: %+v", step.after, op)
		}
		if len(checker.requests) != step.checks {
			t.Fatalf("recovery retry budget changed after %v: checks=%d want=%d", step.after, len(checker.requests), step.checks)
		}
	}
	if status := a.nodeRecoverySnapshot(); status.State != "requires-review" || status.Attempt != 3 {
		t.Fatalf("inner retry exhaustion was bypassed: %+v", status)
	}
	current, _, err := a.Dataplane.Committed()
	if err != nil || !reflect.DeepEqual(current, previous) || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("failed exact checks changed applied authority or configuration")
	}
}

func TestReconcilerRecoveryStartupDropsOldOuterBackoff(t *testing.T) {
	a, _, adapter, checker, previous := nodeRecoveryFixture(t)
	now := time.Now()
	initRecoveryScheduleFixture(t, a, now)
	op := &a.reconciler.doc.Operations[0]
	op.State, op.Reason, op.Attempts = "backoff", "operation-retry", 6
	op.NextRun = now.Add(16 * time.Minute)
	if err := a.persistReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Load the actual durable document, as startup does, rather than erasing
	// its pending operation or granting cached node evidence authority.
	if err := a.loadReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	opValue := recoveryScheduleOperation(t, a)
	if opValue.Attempts != 0 || !opValue.NextRun.IsZero() {
		t.Fatalf("startup inherited stale outer backoff: %+v", opValue)
	}
	a.reconcileRound(context.Background(), now)
	current, _, err := a.Dataplane.Committed()
	if err != nil || a.nodeRecoverySnapshot().State != "recovered" || len(checker.requests) != 1 || current.PlanID == previous.PlanID || current.NetworkProfileID != recoveryProfile || len(adapter.calls) == 0 {
		t.Fatalf("startup did not freshly recover applied target: status=%+v checks=%d err=%v", a.nodeRecoverySnapshot(), len(checker.requests), err)
	}
	if !reflect.DeepEqual(current.Routes, previous.Routes) {
		t.Fatal("startup recovery changed applied targets")
	}
}

func TestReconcilerRecoveryNewAuthorityDoesNotInheritPriorRetryDelay(t *testing.T) {
	for _, change := range []string{"network", "applied-plan"} {
		t.Run(change, func(t *testing.T) {
			a, _, adapter, checker, previous := nodeRecoveryFixture(t)
			now := time.Now()
			initRecoveryScheduleFixture(t, a, now)
			checker.fail = true
			a.reconcileRound(context.Background(), now)
			a.reconcileRound(context.Background(), now.Add(time.Minute))
			if status := a.nodeRecoverySnapshot(); status.Attempt != 2 || !status.NextAttemptAt.Equal(now.Add(5*time.Minute)) {
				t.Fatalf("missing prior task retry delay: %+v", status)
			}
			profile := recoveryProfile
			if change == "network" {
				profile = "wan-333333333333"
				a.FreshProfile = func(context.Context) (string, error) { return profile, nil }
				a.Dataplane.FreshProfile = a.FreshProfile
			} else {
				// Represent a separately committed, still exactly authorized plan.
				// The source scope changes through the actual applied-store API.
				sources := []string{"192.168.1.44/32"}
				_, err := a.Store.ApplyNodeRouteScopeWithRollback("telegram", previous.Routes[0].Selected, sources, a.Store.Get().Revision)
				if err != nil {
					t.Fatal(err)
				}
				previous.PlanID += "-new-authority"
				previous.Revision = a.Store.Get().AppliedRevision
				previous.Routes[0].Sources = sources
				if err := a.Dataplane.Record(previous); err != nil {
					t.Fatal(err)
				}
			}
			checker.fail = false
			a.reconcileRound(context.Background(), now.Add(90*time.Second))
			current, _, err := a.Dataplane.Committed()
			if err != nil || a.nodeRecoverySnapshot().State != "recovered" || a.nodeRecoverySnapshot().Attempt != 1 || len(checker.requests) != 3 || current.NetworkProfileID != profile || len(adapter.calls) == 0 {
				t.Fatalf("new authority waited for the old task: status=%+v checks=%d err=%v", a.nodeRecoverySnapshot(), len(checker.requests), err)
			}
			if !reflect.DeepEqual(current.Routes, previous.Routes) {
				t.Fatal("recovery changed the newly applied scope")
			}
		})
	}
}

func TestReconcilerRecoveryWakeDoesNotEraseExactCheckBackoff(t *testing.T) {
	a, _, _, checker, _ := nodeRecoveryFixture(t)
	now := time.Now()
	initRecoveryScheduleFixture(t, a, now)
	checker.fail = true
	a.reconcileRound(context.Background(), now)
	want := a.nodeRecoverySnapshot()
	a.wakeReconciler()
	if op := recoveryScheduleOperation(t, a); !op.NextRun.IsZero() || op.Attempts != 0 {
		t.Fatalf("settings change did not wake recovery observation: %+v", op)
	}
	a.reconcileRound(context.Background(), now.Add(time.Second))
	if got := a.nodeRecoverySnapshot(); !reflect.DeepEqual(got, want) || len(checker.requests) != 1 {
		t.Fatalf("wake bypassed exact check backoff: %+v checks=%d", got, len(checker.requests))
	}
}

func TestReconcilerRecoveryRetainsRealForwardingFailureAtBoundedCadence(t *testing.T) {
	a, _, adapter, checker, previous := nodeRecoveryFixture(t)
	now := time.Now()
	initRecoveryScheduleFixture(t, a, now)
	// A mismatched applied revision is an ownership failure, not the plain
	// stale-network handoff. It must never be reported as successful recovery.
	previous.Revision++
	if err := a.Dataplane.Record(previous); err != nil {
		t.Fatal(err)
	}
	a.reconciler.doc.Operations[0].Attempts = 6
	a.reconcileRound(context.Background(), now)
	op := recoveryScheduleOperation(t, a)
	if op.State != "backoff" || op.Reason != "operation-retry" || op.Attempts != 7 || !op.NextRun.Equal(now.Add(30*time.Second)) {
		t.Fatalf("real forwarding failure was hidden or delayed observation: %+v", op)
	}
	if a.nodeRecoverySnapshot().State != "requires-review" || len(checker.requests) != 0 || len(adapter.calls) != 0 {
		t.Fatal("unreviewed forwarding authority reached probes or activation")
	}
}

func TestReconcilerRecoveryWakeDuringCancellationKeepsActiveAttempt(t *testing.T) {
	a, _, adapter, checker, _ := nodeRecoveryFixture(t)
	now := time.Now()
	initRecoveryScheduleFixture(t, a, now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checker.hook = func(context.Context, dataplane.NodeCheckRequest) {
		a.wakeReconciler()
		cancel()
	}
	a.reconcileRound(ctx, now)
	op := recoveryScheduleOperation(t, a)
	if op.State != "backoff" || op.Attempts != 1 || !op.NextRun.Equal(now.Add(30*time.Second)) || len(adapter.calls) != 0 {
		t.Fatalf("wake lost the active canceled attempt: %+v", op)
	}
	if release, err := a.Operations.Exclusive(context.Background()); err != nil {
		t.Fatal("canceled recovery retained operation ownership", err)
	} else {
		release()
	}
}
