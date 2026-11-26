package app

import (
	"context"
	"errors"
	"testing"

	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// Original Store/control/scope/Gate; only physical/WAN leaves are models.
func TestListScopePureComparisonClosesWholeActualOwnerEvenOnMismatch(t *testing.T) {
	a, b, physical := listScopeFixture(t, "mac", false)
	listScopeOperation(t, a, func(ctx context.Context) {
		compiled := listScopeCompilation(t, ctx, a, b)
		if err := b.BindCompilation(ctx, compiled); err != nil {
			t.Fatal(err)
		}
		before := physical.checks
		if err := b.ScopeCheck(ctx, compiled.LAN()); err != nil || physical.checks-before != 1 {
			t.Fatal("pure comparison lost fresh closing owner", err, physical.checks-before)
		}
		before = physical.checks
		if err := b.ScopeCheck(ctx, nil); !errors.Is(err, ErrListScopeChanged) || physical.checks-before != 1 {
			t.Fatal("mismatched plan skipped original closing owner", err, physical.checks-before)
		}
		// A bad proposal alone leaves the real owner usable; an actual physical
		// failure during the closing read poisons it permanently.
		physical.verifyErr = physicalscope.ErrUnknown
		before = physical.checks
		if err := b.ScopeCheck(ctx, nil); !errors.Is(err, physicalscope.ErrUnknown) || physical.checks-before != 1 {
			t.Fatal("mismatch hid actual physical failure", err, physical.checks-before)
		}
		physical.verifyErr = nil
		if err := b.ScopeCheck(ctx, compiled.LAN()); err == nil {
			t.Fatal("physical restoration revived invalid owner")
		}
	})
}
