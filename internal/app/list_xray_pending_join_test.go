package app

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestXrayPendingJoinDeadlineAndOriginalOwner(t *testing.T) {
	type key struct{}
	original, expire := context.WithCancel(context.WithValue(context.Background(), key{}, "original"))
	expire()
	for _, tc := range []struct {
		name         string
		parent, want time.Duration
		stop, pair   bool
	}{
		{"first-apply", 4 * time.Minute, 4 * time.Minute, false, false},
		{"short-caller", time.Second, time.Second, false, false},
		{"long-caller", time.Hour, defaultDataplaneApplyTimeout, false, false},
		{"pending-stop", time.Minute, 15 * time.Second, true, false},
		{"replacement", time.Minute, 15 * time.Second, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &managedXraySelectedTCPListExecution{pendingContext: original, pendingStop: tc.stop}
			if tc.pair {
				e.previous = &managedXraySelectedTCPListExecution{}
			}
			parent, cancel := context.WithTimeout(context.WithValue(context.Background(), key{}, "caller"), tc.parent)
			defer cancel()
			started := time.Now()
			ctx, release, err := e.pendingJoinContext(parent)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			deadline, bounded := ctx.Deadline()
			parentDeadline, _ := parent.Deadline()
			if !bounded || deadline.After(parentDeadline) || deadline.Before(started.Add(tc.want-200*time.Millisecond)) || deadline.After(time.Now().Add(tc.want)) {
				t.Fatalf("cleanup deadline %v, wanted %v", time.Until(deadline), tc.want)
			}
			cancel()
			if ctx.Err() != nil || ctx.Value(key{}) != "original" {
				t.Fatal("admitted cleanup lost its original owner or was canceled by the caller")
			}
			release()
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatal("cleanup context not released")
			}
		})
	}
	for _, p := range []context.Context{nil, context.Background(), original} {
		e := &managedXraySelectedTCPListExecution{pendingContext: original}
		if ctx, done, err := e.pendingJoinContext(p); err == nil || ctx != nil || done != nil {
			t.Fatal("admitted missing or expired caller")
		}
	}
}

func TestXrayPendingJoinRefusesAnotherLiveExecution(t *testing.T) {
	a, _, _, _ := serviceRuntimeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cleanup, err := a.Operations.ReviewExclusiveCleanup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy := &managedListPolicyOwner{app: a, manager: a.Dataplane}
	policy.self = policy
	r := &ManagedXraySelectedTCPListRuntime{app: a, manager: a.Dataplane, policy: policy}
	r.self, a.managedXraySelectedTCPList = r, r
	active := &managedXraySelectedTCPListExecution{runtime: r}
	active.self, r.active = active, active
	other, closeOther, err := r.operation(ctx, active, cleanup)
	if err != nil {
		t.Fatal(err)
	}
	defer closeOther()
	closed := false
	e := &managedXraySelectedTCPListExecution{runtime: r, pendingContext: other, pendingRelease: func() { closed = true }, pendingCloseOperation: func() { closed = true }}
	e.self, r.pending = e, e
	if err := r.joinPending(ctx); !errors.Is(err, ErrXrayListSource) {
		t.Fatalf("pending slot accepted the operation of a different active execution: %v", err)
	}
	if closed || r.pending != e || r.active != active || r.stopped != nil {
		t.Fatal("mismatched join released an original owner")
	}
}
