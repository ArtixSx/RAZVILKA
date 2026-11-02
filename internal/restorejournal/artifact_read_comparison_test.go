package restorejournal

import (
	"context"
	"testing"
	"time"
)

func TestArtifactComparisonUnissuedCannotRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, proof := range []*ArtifactSourceComparison{nil, {}, {open: true, ctx: ctx}} {
		if proof.MatchHeld(ctx, nil) == nil {
			t.Fatal("unissued comparison admitted")
		}
	}
	called := false
	if err := new(ArtifactFileTarget).WithReadComparison(ctx, func(context.Context, Image, *ArtifactSourceComparison) error { called = true; return nil }); err == nil || called {
		t.Fatal("unissued target issued comparison")
	}
}
