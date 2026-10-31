package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestNFQWS2HookPreJournalRefusalDoesNotInventRecovery(t *testing.T) {
	for _, mode := range []string{"canceled-after-admission", "authority-refused-before-admission", "already-fenced"} {
		t.Run(mode, func(t *testing.T) {
			a, _, model := nfqws2HookAppFixture(t)
			before := a.Store.Get()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			admissions := 0
			if err := a.Operations.SetGuard(func(context.Context) error {
				admissions++
				if admissions == 2 {
					switch mode {
					case "canceled-after-admission":
						// Cancellation can arrive after the admission's initial
						// context check while its durable guard is returning.
						cancel()
					case "authority-refused-before-admission":
						return errNFQWS2HookAuthority
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if mode == "already-fenced" {
				model.observe = func(context.Context, dataplane.Plan) {
					a.Operations.FenceJournal()
				}
			}

			err := a.restoreNFQWS2HooksRound(ctx, time.Now())
			if mode == "canceled-after-admission" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation was not preserved: %v", err)
				}
			} else if err != nil {
				t.Fatalf("refused admission should leave repair for another round: %v", err)
			}
			if errors.Is(err, ErrNFQWS2HookRecovery) {
				t.Fatalf("refusal before any journal attempt invented recovery: %v", err)
			}
			if model.observed != 1 || model.restored != 0 {
				t.Fatalf("unexpected runtime work: observed=%d restored=%d", model.observed, model.restored)
			}
			if _, err := os.Lstat(filepath.Join(a.Dataplane.StateRoot, nfqws2HookJournalName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("pre-journal refusal created a recovery marker: %v", err)
			}
			if !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("pre-journal refusal changed settings")
			}
			wantFenced := mode == "already-fenced"
			if got := a.Operations.Snapshot().Fenced; got != wantFenced {
				t.Fatalf("fenced=%v, want %v", got, wantFenced)
			}
			_, release, err := a.Operations.ExclusiveContext(context.Background())
			if wantFenced {
				if release != nil {
					release()
				}
				if !errors.Is(err, operationgate.ErrJournalRecovery) {
					t.Fatalf("pre-existing journal fence was cleared: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("effect-free refusal blocked the next admission: %v", err)
				}
				release()
			}
		})
	}
}
