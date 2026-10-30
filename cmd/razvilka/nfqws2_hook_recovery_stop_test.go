package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestOfflineHookRecoveryStopDispatch(t *testing.T) {
	for _, mode := range []string{"loss", "ambiguous-full", "stop-failed", "absence-failed"} {
		t.Run(mode, func(t *testing.T) {
			var calls []string
			denied := errors.New("review refused")
			_, err := runReviewedDataplaneDeactivation(func() (func() error, func(), error) {
				calls = append(calls, "review")
				if mode == "ambiguous-full" {
					return nil, nil, denied
				}
				return func() error {
					calls = append(calls, "fresh-inactive-and-settle")
					if mode == "absence-failed" {
						return denied
					}
					return nil
				}, func() { calls = append(calls, "close") }, nil
			}, func() (dataplane.Deactivation, error) {
				calls = append(calls, "original-stop")
				if mode == "stop-failed" {
					return dataplane.Deactivation{}, denied
				}
				return dataplane.Deactivation{}, nil
			})
			expected := []string{"review", "original-stop", "fresh-inactive-and-settle", "close"}
			if mode == "ambiguous-full" {
				expected = []string{"review"}
			}
			if mode == "stop-failed" {
				expected = []string{"review", "original-stop", "close"}
			}
			if !reflect.DeepEqual(calls, expected) {
				t.Fatal(calls)
			}
			if (err == nil) != (mode == "loss") {
				t.Fatal(err)
			}
		})
	}
}

func TestIndependentSelfUpdateFencesPendingHookIntent(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "dataplane")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	// Same canonical WAL schema as the App, with no test authority exported.
	j := struct {
		Version  int            `json:"version"`
		State    string         `json:"state"`
		Reason   string         `json:"reason"`
		Plan     dataplane.Plan `json:"plan"`
		Instance string         `json:"instance"`
		Started  time.Time      `json:"started"`
		Finished time.Time      `json:"finished,omitempty"`
	}{Version: 1, State: "pending", Reason: "repair-in-progress", Plan: dataplane.Plan{PlanID: "dp-test", Digest: "test-digest"}, Instance: "original", Started: time.Now().UTC()}
	write := func() {
		t.Helper()
		data, err := json.Marshal(j)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(state, "nfqws2-hooks-recovery.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if err := independentSelfUpdateFences(context.Background(), filepath.Join(root, "config.json"), state); !errors.Is(err, app.ErrNFQWS2HookRecovery) {
		t.Fatal("updater bypassed pending hook recovery", err)
	}
	j.State = "settled"
	j.Reason = "verified-settlement"
	j.Finished = time.Now().UTC()
	write()
	if err := independentSelfUpdateFences(context.Background(), filepath.Join(root, "config.json"), state); err != nil {
		t.Fatal("valid settlement still blocked", err)
	}
	// A settled application journal cannot waive a newer interrupted boot
	// repair, either during startup inspection or in the independent updater.
	bootPath := filepath.Join(state, "nfqws2-boot-hooks.json")
	bootEvidence := []byte(`{"State":"pending"}`)
	if err := os.WriteFile(bootPath, bootEvidence, 0600); err != nil {
		t.Fatal(err)
	}
	for name, inspect := range map[string]func() error{
		"startup": func() error { return checkNFQWS2RecoveryJournals(state) },
		"updater": func() error {
			return independentSelfUpdateFences(context.Background(), filepath.Join(root, "config.json"), state)
		},
	} {
		if err := inspect(); !errors.Is(err, dataplane.ErrExecutionJournal) {
			t.Fatal(name, "bypassed pending boot journal", err)
		}
	}
	if raw, err := os.ReadFile(bootPath); err != nil || string(raw) != string(bootEvidence) {
		t.Fatal("read-only inspection changed recovery evidence", err)
	}
}
