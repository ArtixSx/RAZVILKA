package dataplane

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMihomoActiveCheckingEveryHeaderPhaseRequiresOriginalWriter(t *testing.T) {
	for _, phase := range []string{"checking", "settled", "retiring", "retired"} {
		t.Run(phase, func(t *testing.T) {
			m, _, r, _ := mihomoLiveRecordModel(t)
			e := mihomoCheckingExecutionFixture(t)
			e.MihomoLiveHealthOperation.Phase = phase
			switch phase {
			case "settled":
				e.State, e.FinishedAt = "committed", e.StartedAt
			case "retiring":
				e.State = "rolling-back"
			case "retired":
				e.State, e.FinishedAt = "rolled-back", e.StartedAt
				e.Resources[0].State, e.Resources[0].Phase = "removed", "removed"
			}
			if err := validateExecutionResources(e, phase == "settled" || phase == "retired"); err != nil {
				t.Fatal("test did not isolate valid comparison header", err)
			}
			paths := []string{filepath.Join(r.scope.root, "execution.json"), filepath.Join(m.StateRoot, "latest-execution.json")}
			before := make([][]byte, len(paths))
			for i, path := range paths {
				var err error
				before[i], err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := m.writeExecution(r.scope.root, e); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("decoded header acquired generic writer", err)
			}
			// Even an actual scope cannot publish a copied header without its
			// exact open original check/archive writer and matching cursor.
			r.scope.execution = &e
			if err := m.writeExecutionOwned(r.scope.root, e, r.scope); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("scope alone acquired header writer", err)
			}
			for i, path := range paths {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before[i], after) {
					t.Fatal("refusal changed original journal", err)
				}
			}
		})
	}
}
