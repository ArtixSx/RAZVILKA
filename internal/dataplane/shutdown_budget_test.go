package dataplane

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type shutdownJoinAdapter struct {
	*fakeAdapter
	liveStarted, rollbackStarted chan context.Context
	settleLive, settleRollback   chan struct{}
}

func (a *shutdownJoinAdapter) Activate(ctx context.Context, _ Plan, _ string) error {
	a.liveStarted <- ctx
	select {
	case <-a.settleLive:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *shutdownJoinAdapter) Rollback(ctx context.Context, _ Plan, _ string) error {
	a.rollbackStarted <- ctx
	select {
	case <-a.settleRollback:
		return a.call("rollback")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestCanceledApplyJoinsEnteredPhaseAndFollowingRollback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &shutdownJoinAdapter{
		fakeAdapter: &fakeAdapter{id: "sing-box"},
		liveStarted: make(chan context.Context, 1), rollbackStarted: make(chan context.Context, 1),
		settleLive: make(chan struct{}), settleRollback: make(chan struct{}),
	}
	releaseLive := sync.OnceFunc(func() { close(a.settleLive) })
	releaseRollback := sync.OnceFunc(func() { close(a.settleRollback) })
	defer releaseLive()
	defer releaseRollback()
	m := New(t.TempDir())
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		execution Execution
		err       error
	}
	done := make(chan outcome, 1)
	go func() {
		execution, err := m.Apply(ctx, journalTestPlan(), nil)
		done <- outcome{execution, err}
	}()
	var live context.Context
	select {
	case live = <-a.liveStarted:
	case result := <-done:
		t.Fatal("activation never entered", result.err)
	case <-time.After(10 * time.Second):
		t.Fatal("activation did not start")
	}
	cancel()
	if live.Err() != nil {
		t.Fatal("shutdown interrupted the entered live phase", live.Err())
	}
	select {
	case result := <-done:
		t.Fatal("apply returned before live settlement", result.err)
	default:
	}
	releaseLive()
	select {
	case rollback := <-a.rollbackStarted:
		if rollback.Err() != nil {
			t.Fatal("shutdown prevented bounded rollback", rollback.Err())
		}
	case result := <-done:
		t.Fatal("apply returned before rollback started", result.err)
	case <-time.After(10 * time.Second):
		t.Fatal("rollback did not start after live settlement")
	}
	select {
	case result := <-done:
		t.Fatal("apply returned before rollback settlement", result.err)
	default:
	}
	releaseRollback()
	select {
	case result := <-done:
		if !errors.Is(result.err, context.Canceled) || result.execution.State != "rolled-back" || !a.rollback {
			t.Fatal("shutdown did not join settled rollback", result.execution.State, result.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("apply did not finish after rollback settlement")
	}
}
