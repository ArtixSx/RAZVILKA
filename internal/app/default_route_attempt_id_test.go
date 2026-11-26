package app

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Actual Review, Store and Manager resource admission; the existing physical
// and adapter fixture models remain explicit. No native launch is asserted.
func TestDefaultRouteAttemptIDOriginalReviewReachesManagerScope(t *testing.T) {
	e, _, adapter := defaultRouteExecutorFixture(t)
	first, err := e.Review(context.Background(), defaultRouteListedRoutes())
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.Review(context.Background(), defaultRouteListedRoutes())
	if err != nil {
		t.Fatal(err)
	}
	p, next := first.Plan(), second.Plan()
	if p.PlanID == next.PlanID || p.Digest != next.Digest || first.Digest() != second.Digest() ||
		!reflect.DeepEqual(p.LAN, next.LAN) || !reflect.DeepEqual(p.Routes, next.Routes) {
		t.Fatal("attempt nonce changed complete review identity or was reused")
	}
	opctx, release, err := e.app.Operations.ExclusiveContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx := dataplane.WithReviewGuard(opctx, func(ctx context.Context) error {
		return e.guard(ctx, first, first.cfg, false)
	})
	old := p
	old.PlanID = "dp-" + p.Digest[:16] + "-0123456789abcdef"
	called := false
	if err := e.app.Dataplane.WithExecutionResources(ctx, old, adapter.ID(), func(context.Context) error {
		called = true
		return nil
	}); !errors.Is(err, dataplane.ErrNodeTransitUnavailable) || called {
		t.Fatal("previous producer format reached an execution scope", err)
	}
	if err := e.app.Dataplane.WithExecutionResources(ctx, p, adapter.ID(), func(context.Context) error {
		called = true
		return nil
	}); err != nil || !called || adapter.live || len(adapter.steps) != 0 {
		t.Fatal("original reviewed nonce refused or issued an adapter effect", err)
	}
	if e.app.Store.Get().Revision != first.cfg.Revision || len(p.Digest) != 64 {
		t.Fatal("scope admission changed Store or truncated full digest")
	}
}

func TestDefaultRouteAttemptIDNoncesAreFresh(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 128; i++ {
		id, err := newDefaultRouteAttemptID()
		if err != nil || seen[id] {
			t.Fatal("attempt nonce was not fresh", err)
		}
		seen[id] = true
	}
}
