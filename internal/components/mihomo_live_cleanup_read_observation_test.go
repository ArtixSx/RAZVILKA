package components

import (
	"context"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestMihomoLiveCleanupReadObservationCannotMintOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, v := range []*MihomoLiveCleanupObservation{nil, {}, {cleanup: new(operationgate.ExclusiveCleanupReview)}} {
		if v.Current(ctx) == nil || v.PID() != 0 || v.BoundTo(nil, nil, nil) {
			t.Fatal("unissued cleanup view admitted")
		}
		if _, err := v.ProfileReference(ctx); err == nil {
			t.Fatal("unissued cleanup profile")
		}
	}
	called := false
	if err := (*MihomoLiveProcess)(nil).WithCleanupReadObservation(ctx, new(operationgate.ExclusiveCleanupReview), func(context.Context, *MihomoLiveCleanupObservation) error { called = true; return nil }); err == nil || called {
		t.Fatal("unissued child issued cleanup view")
	}
}
