package app

import (
	"context"
	"errors"
	"testing"
)

func TestNFQWSPacketScopeCheckClosesPureComparisonWithFreshOwner(t *testing.T) {
	a, b, physical := nfqwsPacketFixture(t)
	listScopeOperation(t, a, func(ctx context.Context) {
		compiled := nfqwsPacketCompilation(t, ctx, a, b)
		if err := b.BindCompilation(ctx, compiled); err != nil {
			t.Fatal(err)
		}
		before := physical.current
		if err := b.ScopeCheck(ctx, compiled.LAN()); err != nil {
			t.Fatal(err)
		}
		if physical.current != before+1 {
			t.Fatal("pure comparison duplicated physical observation", physical.current-before)
		}
		// A bad proposal cannot skip closing source inspection or poison a
		// still-current original owner merely by disagreeing with its intent.
		before = physical.current
		if err := b.ScopeCheck(ctx, nil); !errors.Is(err, ErrListScopeChanged) {
			t.Fatal(err)
		}
		if physical.current != before+1 || b.invalid {
			t.Fatal("bad proposal skipped fresh owner or poisoned it")
		}
		if err := b.ScopeCheck(ctx, compiled.LAN()); err != nil {
			t.Fatal(err)
		}
		physical.physicalErr = errors.New("actual structural drift")
		if err := b.ScopeCheck(ctx, compiled.LAN()); !errors.Is(err, physical.physicalErr) || !b.invalid {
			t.Fatal("closing physical drift escaped", err)
		}
	})
}
