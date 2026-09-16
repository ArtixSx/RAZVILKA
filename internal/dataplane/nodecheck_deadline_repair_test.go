package dataplane

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"testing"
	"time"
)

func TestRepair2DeadlineNotFabricatedWANChange(t *testing.T) {
	c := fakeExactNodeChecker(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(20*time.Millisecond))
	defer cancel()
	c.proxyEgress = func(ctx context.Context, _ string) (string, error) { <-ctx.Done(); return "", ctx.Err() }
	cleaned := false
	c.cleanup = func(context.Context, exactNodeSession) error { cleaned = true; return nil }
	r, e := c.Check(ctx, checkedNodeRequest())
	if !errors.Is(e, context.DeadlineExceeded) || !cleaned || r.Available || r.Verdict == evidence.VerdictPass || r.Evidence.Verdict == evidence.VerdictPass || r.ErrorCode != "node-check-deadline" || r.Stage != "deadline" {
		t.Fatal("deadline misclassified or unclean", e, r)
	}
}
