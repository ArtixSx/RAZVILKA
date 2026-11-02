package components

import (
	"context"
	"testing"
	"time"
)

func TestMihomoLiveReadObservationCannotMintOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, view := range []*MihomoLiveObservation{nil, {}, {open: true, ctx: ctx}} {
		if view.Current(ctx) == nil || view.PID() != 0 || view.BoundTo(nil, nil) {
			t.Fatal("unissued view supplied an original child")
		}
		if _, err := view.ProfileReference(ctx); err == nil {
			t.Fatal("unissued profile")
		}
	}
	called := false
	if err := (*MihomoLiveProcess)(nil).WithReadObservation(ctx, func(context.Context, *MihomoLiveObservation) error { called = true; return nil }); err == nil || called {
		t.Fatal("unissued child issued observation")
	}
}
