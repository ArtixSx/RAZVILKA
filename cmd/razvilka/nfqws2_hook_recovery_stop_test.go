package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/dataplane"
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
	check := func(want error) {
		t.Helper()
		if err := checkNFQWS2RecoveryJournals(state); !errors.Is(err, want) {
			t.Fatal("startup hook journal decision", err, "want", want)
		}
		if runtime.GOOS != "linux" {
			// The independent updater refuses earlier when the platform cannot
			// perform the native offline Stop journal read.
			want = app.ErrOfflineNFQWS2Stop
		}
		if err := independentSelfUpdateFences(context.Background(), filepath.Join(root, "config.json"), state); !errors.Is(err, want) {
			t.Fatal("independent updater journal decision", err, "want", want)
		}
	}
	write()
	check(app.ErrNFQWS2HookRecovery)
	j.State = "settled"
	j.Reason = "verified-settlement"
	j.Finished = time.Now().UTC()
	write()
	check(nil)
	// A settled application journal cannot waive a newer interrupted boot
	// repair, either during startup inspection or in the independent updater.
	bootPath := filepath.Join(state, "nfqws2-boot-hooks.json")
	bootEvidence := []byte(`{"State":"pending"}`)
	if err := os.WriteFile(bootPath, bootEvidence, 0600); err != nil {
		t.Fatal(err)
	}
	check(dataplane.ErrExecutionJournal)
	if raw, err := os.ReadFile(bootPath); err != nil || string(raw) != string(bootEvidence) {
		t.Fatal("read-only inspection changed recovery evidence", err)
	}
}
