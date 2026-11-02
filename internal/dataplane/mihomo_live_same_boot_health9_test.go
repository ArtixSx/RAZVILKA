package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Admission refusal only: no native source, five leases or writer is minted.
func TestMihomoSameBootHealth9RequiresCanonicalOriginalFleet(t *testing.T) {
	root := filepath.Join(installpath.State, "dataplane")
	for _, kind := range []string{"no-fleet", "foreign-manager", "foreign-input", "checking", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			before := settledMihomoColdHealth9Fixture(t)
			c := &mihomoSameBootRetirementCursor{ctx: ctx, manager: &Manager{StateRoot: root}, owner: &mihomoSameBootCleanup{inputs: &mihomoSameBootInputs{statePath: root, before: before}}}
			c.self = c
			inspections := 0
			if kind != "no-fleet" {
				c.history = updatecheck.NewExecutionHistoryAdmission(func(context.Context, string) (int, string, error) {
					inspections++
					return 9, "documentary-only", nil
				})
			}
			switch kind {
			case "foreign-manager":
				c.manager.StateRoot = t.TempDir()
			case "foreign-input":
				c.owner.inputs.statePath = t.TempDir()
			case "checking":
				c.owner.inputs.before.MihomoLiveHealthOperation.Phase = "checking"
			case "canceled":
				cancel()
			}
			err := c.checkHistory()
			if err == nil || inspections != 0 {
				t.Fatal("unadmitted original intent reached fleet/publication", err, inspections)
			}
			if kind == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("original cancellation lost", err)
			}
		})
	}
}
