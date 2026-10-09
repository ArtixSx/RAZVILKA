package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestSyntheticBaselinePhaseCarriesActualGateBeforeRequest(t *testing.T) {
	m, a, plan, scope, ctx := syntheticExecutionModel(t)
	gate := &operationgate.Gate{}
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	type phaseValue struct{}
	held = context.WithValue(scope.contextWith(held), phaseValue{}, "original")
	b, err := m.BindSyntheticDNSExecution(held, a, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer b.phase.Close()
	request, cancel := context.WithTimeout(context.WithValue(context.Background(), phaseValue{}, "request"), time.Second)
	defer cancel()
	if err := gate.WithExclusiveContext(request, func() error { t.Fatal("request issued a Gate owner"); return nil }); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal(err)
	}
	err = b.phase.WithRequest(request, func(c context.Context) error {
		if c.Value(phaseValue{}) != "original" || c.Value(syntheticExecutionRegistrarKey{}) != scope {
			t.Fatal("original phase values lost")
		}
		got, _ := c.Deadline()
		want, _ := request.Deadline()
		if !got.Equal(want) {
			t.Fatal("request deadline extended", got, want)
		}
		return gate.WithExclusiveContext(c, func() error { return nil })
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.phase.WithRequest(ctx, func(c context.Context) error {
		got, _ := c.Deadline()
		want, _ := held.Deadline()
		if !got.Equal(want) {
			t.Fatal("original phase deadline extended")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := newSyntheticBaselineExecutionPhase(ctx, b); err == nil {
		t.Fatal("unbound context created original phase")
	}
	if err := (&syntheticBaselineExecutionPhase{self: b.phase}).WithRequest(ctx, func(context.Context) error { t.Fatal("copy entered"); return nil }); err == nil {
		t.Fatal("copied phase accepted")
	}
}

func TestSyntheticBaselinePhaseBothCancellationsAndClosingBookend(t *testing.T) {
	for _, kind := range []string{"request", "phase", "scope", "registry"} {
		t.Run(kind, func(t *testing.T) {
			m, a, plan, scope, ctx := syntheticExecutionModel(t)
			original, cancelPhase := context.WithCancel(scope.contextWith(ctx))
			defer cancelPhase()
			b, err := m.BindSyntheticDNSExecution(original, a, plan)
			if err != nil {
				t.Fatal(err)
			}
			defer b.phase.Close()
			request, cancelRequest := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelRequest()
			err = b.phase.WithRequest(request, func(c context.Context) error {
				switch kind {
				case "request":
					cancelRequest()
				case "phase":
					cancelPhase()
				case "scope":
					scope.cancel()
				case "registry":
					return m.Register(&fakeAdapter{id: "other-phase-model"})
				}
				select {
				case <-c.Done():
					return nil // Nominal success cannot defeat the closing check.
				case <-request.Done():
					return errors.New("phase failed to forward cancellation")
				}
			})
			if err == nil {
				t.Fatal("closing cancellation/drift accepted")
			}
			if kind != "registry" && !errors.Is(err, context.Canceled) {
				t.Fatal("original cancellation lost", err)
			}
		})
	}
}

func TestSyntheticBaselinePhaseCloseRevokesThenJoinsBorrower(t *testing.T) {
	m, a, plan, scope, ctx := syntheticExecutionModel(t)
	b, err := m.BindSyntheticDNSExecution(scope.contextWith(ctx), a, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer b.phase.Close()
	entered, cancelled, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
	used, joined := make(chan error, 1), make(chan error, 1)
	go func() {
		used <- b.phase.WithRequest(ctx, func(c context.Context) error {
			close(entered)
			<-c.Done()
			close(cancelled)
			<-finish
			return nil
		})
	}()
	<-entered
	go func() { joined <- b.phase.Close() }()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited before revoking borrower")
	}
	select {
	case <-joined:
		t.Fatal("Close returned before borrower joined")
	default:
	}
	if err := b.phase.WithRequest(ctx, func(context.Context) error { t.Fatal("late use entered"); return nil }); err == nil {
		t.Fatal("closing carrier reopened")
	}
	close(finish)
	if err := <-used; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := <-joined; err != nil {
		t.Fatal(err)
	}
	if err := b.phase.Close(); err != nil {
		t.Fatal("idempotent join", err)
	}
}
