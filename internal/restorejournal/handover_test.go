package restorejournal

import (
	"context"
	"errors"
	"testing"
)

func TestHandoverKeepsDecisionUntilCachesAreReady(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		for _, fail := range []bool{false, true} {
			j, path, targets, list := fixture(t)
			if rollback {
				list[2].hook = func(Image, Image) error { return injected }
			}
			calls := 0
			out, err := j.ExecuteWithHandover(context.Background(), changes(), func() error {
				calls++
				doc, err := j.load()
				if err != nil {
					t.Fatal(err)
				}
				want := "committed"
				if rollback {
					want = "prepared"
					expectOld(t, list)
				}
				if doc.State != want {
					t.Fatal("decision cleared before handover", doc.State)
				}
				if fail {
					return injected
				}
				return nil
			})
			if calls != 1 {
				t.Fatal("handover count", calls)
			}
			if fail {
				if out != Blocked || !errors.Is(err, ErrRecovery) {
					t.Fatal(out, err)
				}
				list[2].hook = nil
				next := reopen(t, j, path, targets)
				out, err = next.Recover(context.Background())
				if err != nil {
					t.Fatal(err)
				}
			}
			want := Applied
			if rollback {
				want = RolledBack
			}
			if out != want {
				t.Fatal(out, want)
			}
		}
	}
}

func TestHandoverNotCalledBeforePrepared(t *testing.T) {
	j, _, _, _ := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	out, err := j.ExecuteWithHandover(ctx, changes(), func() error { calls++; return nil })
	if out != Clean || err == nil || calls != 0 {
		t.Fatal(out, err, calls)
	}
}
