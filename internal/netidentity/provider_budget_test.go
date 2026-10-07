package netidentity

import (
	"context"
	"testing"
	"time"
)

func TestProviderStockAggregateAndTwoSecondLeaves(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), "budget-operation", "original"), 30*time.Second)
	defer cancel()
	for _, stock := range []bool{false, true} {
		p := modelProvider(!stock, stock)
		read, build := p.read, p.build
		checkLeaf := func(c context.Context) {
			t.Helper()
			deadline, ok := c.Deadline()
			remaining := time.Until(deadline)
			if !ok || remaining <= 0 || remaining > 2100*time.Millisecond || c.Value("budget-operation") != "original" {
				t.Fatal("leaf lost original bounded context")
			}
		}
		p.read = func(c context.Context) (observation, error) { checkLeaf(c); return read(c) }
		p.build = func(c context.Context) (buildTuple, error) { checkLeaf(c); return build(c) }
		if _, err := p.Observe(ctx); err != nil {
			t.Fatal(err)
		}
		if err := p.WithCurrent(ctx, func(c context.Context, _ Identity) error {
			deadline, ok := c.Deadline()
			remaining := time.Until(deadline)
			if !ok || remaining <= 0 || c.Value("budget-operation") != "original" {
				t.Fatal("aggregate context replaced")
			}
			if stock {
				if remaining < 15*time.Second || remaining > 16100*time.Millisecond {
					t.Fatal("stock aggregate not finite16s", remaining)
				}
			} else if remaining > 2100*time.Millisecond {
				t.Fatal("generic Linux aggregate expanded")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
func TestProviderStockCallbackBeyondOldTwoSecondCutoff(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p := modelProvider(false, true)
	if err := p.WithCurrent(ctx, func(c context.Context, _ Identity) error {
		timer := time.NewTimer(2100 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			return c.Err()
		case <-c.Done():
			return c.Err()
		}
	}); err != nil {
		t.Fatal("stock aggregate truncated actual finite callback", err)
	}
}
func TestProviderStockShorterCallerDeadlineAndClosingDrift(t *testing.T) {
	parent, cancel := context.WithTimeout(context.WithValue(context.Background(), "budget-operation", "original"), time.Second)
	defer cancel()
	p := modelProvider(false, true)
	if err := p.WithCurrent(parent, func(c context.Context, _ Identity) error {
		outer, _ := parent.Deadline()
		inner, _ := c.Deadline()
		if inner.After(outer) || c.Value("budget-operation") != "original" {
			t.Fatal("shorter caller deadline renewed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	read := p.read
	reads := 0
	p.read = func(c context.Context) (observation, error) {
		o, err := read(c)
		reads++
		if reads == 3 {
			o.BootID = "11234567-89ab-cdef-0123-456789abcdef"
		}
		return o, err
	}
	if p.WithCurrent(parent, func(context.Context, Identity) error { return nil }) == nil {
		t.Fatal("longer budget adopted closing drift")
	}
	p = modelProvider(false, true)
	if p.WithCurrent(parent, func(context.Context, Identity) error { cancel(); return nil }) == nil {
		t.Fatal("cancelled nil callback adopted")
	}
	if p.WithCurrent(context.Background(), func(context.Context, Identity) error { return nil }) == nil {
		t.Fatal("missing original deadline accepted")
	}
}
