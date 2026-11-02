package updatecheck

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func TestExecutionHistoryRequiresEveryRetainedController(t *testing.T) {
	for _, version := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8} {
		i := componentAdmissionFixture(t)
		componentAdmissionOldController(t, i)
		a := NewExecutionHistoryAdmission(func(context.Context, string) (int, string, error) { return 1, "unchanged", nil })
		a.inventory = i
		a.probe = func(context.Context, selfupdatejournal.BinaryImage) (int, error) { return version, nil }
		if err := a.CheckWrite(context.Background()); (err == nil) != (version == ExecutionHistoryReadVersion) {
			t.Fatalf("reader %d: %v", version, err)
		}
	}
}

func TestExecutionHistoryRequestedFormatCannotBypassExistingHistory(t *testing.T) {
	for _, retained := range []int{1, 2, 3, 4, 5, 6, 7, 8} {
		for _, old := range []int{1, 2, 3, 4, 5, 6, 7, 8} {
			for _, wanted := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8} {
				t.Run(fmt.Sprintf("history%d/old%d/wanted%d", retained, old, wanted), func(t *testing.T) {
					i := componentAdmissionFixture(t)
					componentAdmissionOldController(t, i)
					a := NewExecutionHistoryAdmission(func(context.Context, string) (int, string, error) { return retained, "unchanged", nil })
					a.inventory = i
					a.probe = func(context.Context, selfupdatejournal.BinaryImage) (int, error) { return old, nil }
					want := wanted >= 1 && wanted <= ExecutionHistoryReadVersion && retained <= ExecutionHistoryReadVersion && old <= ExecutionHistoryReadVersion && old >= max(retained, wanted)
					if err := a.CheckWrite(context.Background(), wanted); (err == nil) != want {
						t.Fatal("wrong minimum reader admission", err)
					}
					if a.CheckWrite(context.Background(), wanted, wanted) == nil {
						t.Fatal("ambiguous requested formats accepted")
					}
				})
			}
		}
	}
}

func TestExecutionHistoryAdmissionRejectsBookendDrift(t *testing.T) {
	for _, change := range []string{"history", "binary", "inventory", "cancel"} {
		t.Run(change, func(t *testing.T) {
			i := componentAdmissionFixture(t)
			old := componentAdmissionOldController(t, i)
			seal := "first"
			a := NewExecutionHistoryAdmission(func(context.Context, string) (int, string, error) { return 1, seal, nil })
			a.inventory = i
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a.probe = func(context.Context, selfupdatejournal.BinaryImage) (int, error) {
				switch change {
				case "history":
					seal = "second"
				case "binary":
					if err := os.WriteFile(old, []byte("replacement"), 0600); err != nil {
						t.Fatal(err)
					}
				case "inventory":
					retainedFile(t, i.stateRoot, "update-backups/new/razvilka.bin", []byte("unsealed image"))
				case "cancel":
					cancel()
				}
				return 4, nil
			}
			if a.CheckWrite(ctx) == nil {
				t.Fatal("changed history/owner accepted")
			}
		})
	}
}

func TestExecutionHistoryCandidateUsesExactFlagAndCompleteSeal(t *testing.T) {
	for _, response := range []string{"1\n", "2\n", "3\n", "4\n", "5\n", "6\n", "7\n", "02\n", "2", "2\nextra"} {
		called := false
		probe := func(_ context.Context, path, flag string) (string, error) {
			called = true
			if path != "candidate" || flag != "-dataplane-execution-read-version" {
				t.Fatal("wrong metadata", path, flag)
			}
			return response, nil
		}
		inspect := func(context.Context, string) (int, string, error) { return 2, "same", nil }
		err := checkExecutionHistoryCapability(context.Background(), "candidate", "root", probe, inspect)
		if !called || (err == nil) != (response == "2\n" || response == "3\n" || response == "4\n" || response == "5\n" || response == "6\n" || response == "7\n") {
			t.Fatal(response, err)
		}
	}
	count := 0
	inspect := func(context.Context, string) (int, string, error) {
		count++
		if count == 1 {
			return 2, "before", nil
		}
		return 2, "after", nil
	}
	if checkExecutionHistoryCapability(context.Background(), "candidate", "root", func(context.Context, string, string) (string, error) { return "2\n", nil }, inspect) == nil {
		t.Fatal("history changed during capability read")
	}
}

func TestExecutionHistoryMissingScannerOnlyAcceptsAbsentDirectory(t *testing.T) {
	a := NewSelfUpdateFileAdapter()
	path := filepath.Join(t.TempDir(), "absent")
	if v, _, err := a.inspectExecutionHistory(context.Background(), path); err != nil || v != 1 {
		t.Fatal(v, err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.inspectExecutionHistory(context.Background(), path); !errors.Is(err, ErrExecutionHistoryAdmission) {
		t.Fatal("existing unclassified history accepted", err)
	}
}
