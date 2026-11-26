package nativeowner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Real accepted CORE Gate/control/cleanup types, fixture-local control state.
// No native process, account or network action occurs. The review predicate is
// frozen to this test's original request owner; never an unconditional grant.
func coreFixture(t *testing.T) (*operationgate.Gate, context.Context, func(), COREBinding) {
	t.Helper()
	f := fixtureOwner(t)
	gate := &operationgate.Gate{}
	root := filepath.Join(t.TempDir(), "TEST-ONLY-control")
	if _, err := operationgate.InitializeSelfUpdateControl(f.ctx, root); err != nil {
		t.Fatal(err)
	}
	original, release, err := gate.ExclusiveContext(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	expected := f.acquisition.Request
	b := COREBinding{Request: expected, Helper: f.helper, ControlRoot: root, TransactionID: strings.Repeat("a", 32), Review: func(ctx context.Context) error {
		if ctx.Err() != nil || f.acquisition.Request != expected {
			return ErrOwned
		}
		return nil
	}}
	return gate, original, release, b
}

func TestOwnerCOREFactoryRequiresActualOriginalSameGate(t *testing.T) {
	gate, ctx, release, b := coreFixture(t)
	defer release()
	if f, err := NewCOREFactory(ctx, gate, b); err != nil {
		t.Fatal(err)
	} else {
		_ = f.(*coreFactory).epoch.Close()
	}
	foreign := &operationgate.Gate{}
	for _, pair := range []struct {
		ctx  context.Context
		gate *operationgate.Gate
	}{{context.Background(), gate}, {ctx, foreign}} {
		if f, err := NewCOREFactory(pair.ctx, pair.gate, b); err == nil || f != nil {
			t.Fatal("plain/foreign original scope granted")
		}
	}
	release()
	if f, err := NewCOREFactory(ctx, gate, b); err == nil || f != nil {
		t.Fatal("released original scope granted")
	}
}

func TestOwnerCOREFactoryControlStopRevokesForward(t *testing.T) {
	gate, ctx, release, b := coreFixture(t)
	defer release()
	original, err := NewCOREFactory(ctx, gate, b)
	if err != nil {
		t.Fatal(err)
	}
	f := original.(*coreFactory)
	defer f.epoch.Close()
	if f.forward(ctx) != nil {
		t.Fatal("original forward not current")
	}
	if _, err := operationgate.RequestSelfUpdateStop(ctx, b.ControlRoot, strings.Repeat("b", 32), 1); err != nil {
		t.Fatal(err)
	}
	if f.forward(ctx) == nil {
		t.Fatal("durable Stop ignored")
	}
}

func TestOwnerCOREFactoryCleanupKeepsOriginalLifetimeAfterCancel(t *testing.T) {
	gate, owned, release, b := coreFixture(t)
	request, cancel := context.WithCancel(owned)
	original, err := NewCOREFactory(request, gate, b)
	if err != nil {
		release()
		t.Fatal(err)
	}
	f := original.(*coreFactory)
	scope := Scope{Acquisition: fixtureOwner(t).acquisition, Helper: b.Helper}
	scope.Acquisition.Request = b.Request
	scope.Deadline, _ = request.Deadline()
	l, err := f.Acquire(request, scope)
	if err != nil {
		release()
		t.Fatal(err)
	}
	cancel()
	cleanup, done := context.WithTimeout(context.WithoutCancel(owned), time.Second)
	defer done()
	if l.Current(cleanup) == nil {
		t.Fatal("WithoutCancel renewed forward")
	}
	called := false
	if l.WithCleanup(cleanup, func() error { called = true; return nil }) != nil || !called {
		t.Fatal("original cleanup lifetime lost after cancellation")
	}
	if l.Release(cleanup) != nil {
		t.Fatal("known fixture-only original cleanup release failed")
	}
	release()
}
