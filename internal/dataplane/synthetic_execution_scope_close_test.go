package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Uses the actual finite Manager/scope/phase protocol with explicitly modeled
// physical readers. No socket, capture, publication or native grant exists.
func TestSyntheticExecutionScopeCancelsAllBorrowersBeforeStartBarrierAndRootRelease(t *testing.T) {
	m, a, plan, scope, ctx := syntheticExecutionModel(t)
	first, err := m.BindSyntheticDNSExecution(scope.contextWith(ctx), a, plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.BindSyntheticDNSExecution(scope.contextWith(ctx), a, plan)
	if err != nil {
		t.Fatal(err)
	}
	entered, cancelled, finish := make(chan struct{}, 2), make(chan struct{}, 2), make(chan struct{})
	// Current holds the actual start read barrier through this guard. A Close
	// that takes the writer barrier before cancelling the phases deadlocks.
	scope.guard = func(c context.Context) error {
		entered <- struct{}{}
		<-c.Done()
		cancelled <- struct{}{}
		<-finish
		return c.Err()
	}
	used := make(chan error, 2)
	for _, b := range []*SyntheticDNSExecutionBinding{first, second} {
		go func() {
			used <- b.phase.WithRequest(ctx, func(context.Context) error {
				t.Error("cancelled opening owner entered request")
				return nil
			})
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("borrower did not enter original Current")
		}
	}
	joined := make(chan error, 2)
	go func() { joined <- scope.close() }()
	go func() { joined <- scope.close() }()
	for range 2 {
		select {
		case <-cancelled:
		case <-time.After(5 * time.Second):
			t.Fatal("Close joined a borrower before cancelling every phase")
		}
	}
	if scope.ctx.Err() != nil {
		t.Fatal("scope cancellation preceded live Start barrier")
	}
	if _, err := scope.owned.RootInfo(); err != nil {
		t.Fatal("original root released before borrowers joined")
	}
	if err := scope.registerSyntheticPhase(scope.contextWith(ctx), first); err == nil {
		t.Fatal("closing scope admitted another phase registration")
	}
	select {
	case <-joined:
		t.Fatal("scope returned before borrower completed")
	default:
	}
	close(finish)
	for range 2 {
		if err := <-used; !errors.Is(err, context.Canceled) {
			t.Fatal("original cancellation lost", err)
		}
		if err := <-joined; err != nil {
			t.Fatal("idempotent actual scope join failed", err)
		}
	}
	if !first.phase.closed.Load() || !second.phase.closed.Load() || scope.ctx.Err() == nil {
		t.Fatal("finite phase or scope survived original close")
	}
}

func TestSyntheticExecutionScopeRegistrationClosesOriginalRegistryBookend(t *testing.T) {
	m, a, plan, scope, ctx := syntheticExecutionModel(t)
	b, err := m.BindSyntheticDNSExecution(scope.contextWith(ctx), a, plan)
	if err != nil {
		t.Fatal(err)
	}
	// Model the exact gap between the actual phase's final Current and its
	// registration. The existing registered original phase remains distinct.
	pending := &SyntheticDNSExecutionBinding{scope: scope, adapter: a, plan: b.plan, domain: b.domain, transport: b.transport, dns: b.dns, root: b.root}
	pending.self = pending
	pending.phase, err = newSyntheticBaselineExecutionPhase(scope.contextWith(ctx), pending)
	if err != nil {
		t.Fatal(err)
	}
	defer pending.phase.Close()
	if err := m.Register(&fakeAdapter{id: "changed-before-phase-registration"}); err != nil {
		t.Fatal(err)
	}
	if err := scope.registerSyntheticPhase(scope.contextWith(ctx), pending); !errors.Is(err, ErrNodeTransitUnavailable) {
		t.Fatal("changed original registry published a phase", err)
	}
	if len(scope.syntheticPhases) != 1 {
		t.Fatal("refused phase entered the original registry")
	}
}
