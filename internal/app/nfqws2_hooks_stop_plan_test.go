package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNFQWS2HookOfflineStopRetainsCommittedPlan(t *testing.T) {
	for _, during := range []bool{false, true} {
		name := "before-absence"
		if during {
			name = "during-absence"
		}
		t.Run(name, func(t *testing.T) {
			a, p, model := nfqws2HookAppFixture(t)
			o, err := beginNFQWS2HookJournal(a.Dataplane.StateRoot, p, model.instance)
			if err != nil {
				t.Fatal(err)
			}
			defer o.root.Close()
			replace := func() {
				t.Helper()
				changed := p
				// Keep the identifiers: a full plan comparison must detect a
				// changed scope even when an old digest is copied with it.
				changed.Revision++
				data, err := json.Marshal(changed)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(a.Dataplane.StateRoot, "latest-committed-plan.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if !during {
				replace()
			}
			settle := nfqws2HookStopSettlement(context.Background(), a.Dataplane, o, func() error {
				if during {
					replace()
				}
				return nil
			})
			if err := settle(); err == nil {
				t.Fatal("offline Stop settled a hook journal after the committed plan changed")
			}
			if err := CheckNFQWS2HookRecovery(a.Dataplane.StateRoot); !errors.Is(err, ErrNFQWS2HookRecovery) {
				t.Fatal("changed plan reopened recovery admission", err)
			}
			current, exists, err := a.Dataplane.Committed()
			if err != nil || !exists || current.Revision != p.Revision+1 || current.Digest != p.Digest {
				t.Fatal("refusal overwrote the competing plan", current, err)
			}
		})
	}
}

func TestNFQWS2HookOfflineStopCanceledObservationRetainsIntent(t *testing.T) {
	for _, before := range []bool{false, true} {
		name := "during-absence"
		if before {
			name = "before-absence"
		}
		t.Run(name, func(t *testing.T) {
			a, p, model := nfqws2HookAppFixture(t)
			o, err := beginNFQWS2HookJournal(a.Dataplane.StateRoot, p, model.instance)
			if err != nil {
				t.Fatal(err)
			}
			defer o.root.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if before {
				cancel()
			}
			observed := 0
			settle := nfqws2HookStopSettlement(ctx, a.Dataplane, o, func() error {
				observed++
				cancel()
				return nil
			})
			if err := settle(); !errors.Is(err, context.Canceled) {
				t.Fatal("canceled Stop observation settled", err)
			}
			if before && observed != 0 || !before && observed != 1 {
				t.Fatal("unexpected observation after cancellation", observed)
			}
			if err := CheckNFQWS2HookRecovery(a.Dataplane.StateRoot); !errors.Is(err, ErrNFQWS2HookRecovery) {
				t.Fatal("cancellation removed pending intent", err)
			}
		})
	}
}
