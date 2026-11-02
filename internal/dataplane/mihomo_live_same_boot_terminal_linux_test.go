//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/privaterestore"
)

// Genuine original five leases, journal slot FDs, no-replace/CAS writers and
// fsync retries; the native cleanup outcome is explicitly a documentary model.
func TestMihomoSameBootTerminalRetainsActualPartialWriterAndRepeatsACK(t *testing.T) {
	sameBootInputsFixture(t, func(ctx context.Context, set *privaterestore.OfflineServiceControlSet, state string, e Execution) {
		i, err := holdMihomoSameBootInputs(ctx, set, state, e.PlanID, e.Digest)
		if err != nil {
			t.Fatal(err)
		}
		defer i.close()
		after, err := mihomoLiveRetirementTerminal(e, time.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(after)
		if err != nil {
			t.Fatal(err)
		}
		c := &mihomoSameBootRetirementCursor{owner: &mihomoSameBootCleanup{inputs: i, effectsClosed: true}, intent: mihomoSameBootIntent{After: wire}}
		c.self = c
		lost := errors.New("actual terminal publication ACK lost")
		c.terminalFault = func(int) error { return lost }
		current := func() error { return i.current(ctx) }
		old := i.records[0].info
		if err := c.publishTerminal(0, current); !errors.Is(err, lost) || !c.terminalPending[0] || c.retryTerminal != 1 || os.SameFile(old, i.records[0].info) {
			t.Fatal("actual published FD/partial ACK not retained", err)
		}
		published := i.records[0].info
		if err := New(state).CheckExecutionRecovery(ctx); !errors.Is(err, ErrExecutionJournal) {
			t.Fatal("partial pair lost actual recovery fence", err)
		}
		c.terminalFault = nil
		if err := c.publishTerminal(0, current); err != nil || c.terminalPending[0] || !os.SameFile(published, i.records[0].info) {
			t.Fatal("retry replaced adopted original inode instead of repeating durability ACK", err)
		}
		if err := c.publishTerminal(1, current); err != nil {
			t.Fatal(err)
		}
		if err := New(state).CheckExecutionRecovery(ctx); err != nil {
			t.Fatal("both actual terminal ACKs remain fenced", err)
		}
	})
}

func TestMihomoSameBootTerminalCloseErrorNeverBecomesRetry(t *testing.T) {
	sameBootInputsFixture(t, func(ctx context.Context, set *privaterestore.OfflineServiceControlSet, state string, e Execution) {
		i, err := holdMihomoSameBootInputs(ctx, set, state, e.PlanID, e.Digest)
		if err != nil {
			t.Fatal(err)
		}
		defer i.close()
		after, err := mihomoLiveRetirementTerminal(e, time.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(after)
		if err != nil {
			t.Fatal(err)
		}
		c := &mihomoSameBootRetirementCursor{owner: &mihomoSameBootCleanup{inputs: i, effectsClosed: true}, intent: mihomoSameBootIntent{After: wire}}
		c.self = c
		old, cut := i.records[0].file, true
		current := func() error {
			if err := i.current(ctx); err != nil {
				return err
			}
			if cut {
				cut = false
				return old.Close()
			} // Actual Close AFTER opening CAS, before original writer replacement.
			return nil
		}
		if err := c.publishTerminal(0, current); !errors.Is(err, os.ErrClosed) || c.retryTerminal != 0 {
			t.Fatal("actual old Close exception lost or classified retry", err)
		}
		published := i.records[0].info
		for range 2 {
			if err := c.publishTerminal(0, current); !errors.Is(err, os.ErrClosed) || !os.SameFile(published, i.records[0].info) {
				t.Fatal("sticky close cause lost or file rewritten", err)
			}
		}
	})
}
