package strategylab

import (
	"context"
	"testing"
	"time"
)

func TestManagedSelectionNeverReconstructsRestoredEpoch(t *testing.T) {
	m, _ := privateFixture(t, managedProbeStateFixture())
	before := m.Snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, mode := range []AdaptiveMode{ModePreferred, ModeOnly, ModeManual, ""} {
		if _, err := m.SelectManaged(ctx, "service", "tcp", "ipv4", "candidate", mode, false); err == nil {
			t.Fatal("restored records manufactured live epoch", mode)
		}
	}
	if len(m.Snapshot().Selections) != len(before.Selections) {
		t.Fatal("failed selection changed manual/history state")
	}
}
