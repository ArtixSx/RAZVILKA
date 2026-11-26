package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func bootStopWAL(t *testing.T) *nfqws2BootHookWAL {
	t.Helper()
	path := t.TempDir()
	r, err := ownedfs.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	j := &nfqws2BootHookWAL{root: r, path: path, record: nfqws2CandidateHookRecord{
		Version: 1, PlanID: "dp-aaaaaaaaaaaaaaaa", Digest: strings.Repeat("a", 64), Instance: strings.Repeat("b", 24), State: "uncertain",
		Effects: []nfqws2CandidateHookEffect{{Command: NFQWS2HookCommand{Family: 4, Args: []string{"-t", "mangle", "-N", "nfqws_post"}}, State: "unknown"}},
	}}
	if err := j.save(); err != nil {
		t.Fatal(err)
	}
	return j
}

func TestNFQWS2BootHookStopRequiresFreshAbsenceAndRetainsEvidence(t *testing.T) {
	j := bootStopWAL(t)
	before := string(j.image)
	denied := errors.New("process or rules still present")
	if err := j.settleStopped(func() error { return denied }); !errors.Is(err, denied) {
		t.Fatal(err)
	}
	if raw, _, err := readNFQWS2BootHookEvidence(j.root); err != nil || string(raw) != before {
		t.Fatal("failed absence changed evidence", err)
	}
	if _, _, err := readNFQWS2BootHookJournal(j.root); !errors.Is(err, ErrExecutionJournal) {
		t.Fatal("failed absence unfenced journal", err)
	}
	if err := j.settleStopped(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	_, record, err := readNFQWS2BootHookJournal(j.root)
	if err != nil || record.State != "stopped" || record.Effects[0].State != "unknown" {
		t.Fatal("settlement discarded uncertain effect", record, err)
	}
}

func TestNFQWS2BootHookStopRefusesChangedEvidenceDuringAbsence(t *testing.T) {
	j := bootStopWAL(t)
	replacement := []byte(`{"state":"another-owner"}`)
	err := j.settleStopped(func() error {
		return os.WriteFile(filepath.Join(j.path, nfqws2BootHookJournal), replacement, 0600)
	})
	if !errors.Is(err, ErrReviewChanged) {
		t.Fatal("replaced evidence accepted", err)
	}
	raw, err := os.ReadFile(filepath.Join(j.path, nfqws2BootHookJournal))
	if err != nil || string(raw) != string(replacement) {
		t.Fatal("replacement overwritten", err)
	}
}

func TestNFQWS2BootHookStopWithoutCommittedOwnerCannotSettle(t *testing.T) {
	j := bootStopWAL(t)
	m := New(j.path)
	settle, closeReview, err := m.ReviewNFQWS2BootHookStop(context.Background(), filepath.Join(j.path, "config.json"))
	if err == nil || settle != nil || closeReview != nil {
		t.Fatal("unbound Stop received settlement authority", err)
	}
	if raw, _, err := readNFQWS2BootHookEvidence(j.root); err != nil || string(raw) != string(j.image) {
		t.Fatal("refused Stop changed evidence", err)
	}
}

func TestNFQWS2BootHookStopDoesNotAcceptUnknownSchemaOrHistory(t *testing.T) {
	for _, change := range []string{"unknown-command", "unknown-state", "unacknowledged-middle", "settled-unknown"} {
		t.Run(change, func(t *testing.T) {
			j := bootStopWAL(t)
			switch change {
			case "unknown-command":
				j.record.Effects[0].Command.Args = []string{"-F"}
			case "unknown-state":
				j.record.State = "ignore-errors"
			case "unacknowledged-middle":
				j.record.Effects = append(j.record.Effects, j.record.Effects[0])
			case "settled-unknown":
				j.record.State = "settled"
			}
			if err := j.save(); err != nil {
				t.Fatal(err)
			}
			if _, _, err := readNFQWS2BootHookEvidence(j.root); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("invalid recovery history admitted", err)
			}
		})
	}
}

func TestNFQWS2BootHookStopRechecksCommittedPlanAndContext(t *testing.T) {
	for _, change := range []string{"unchanged", "before-observation", "during-observation", "missing-plan", "manager-root", "canceled-before", "canceled-during"} {
		t.Run(change, func(t *testing.T) {
			j := bootStopWAL(t)
			m := New(j.path)
			plan := Plan{SchemaVersion: SchemaVersion, PlanID: j.record.PlanID, Digest: j.record.Digest, State: "committed", Ready: true, Adapters: []string{"nfqws2"}}
			writePlan := func(p Plan) {
				t.Helper()
				raw, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				if err = j.root.WriteAtomic("latest-committed-plan.json", raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			writePlan(plan)
			before := string(j.image)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			changed := plan
			// Keep ID/digest unchanged: the whole retained plan, including its
			// intended route scope, must match rather than just these two fields.
			changed.Routes = []Route{{ServiceID: "replacement", Resolved: "nfqws2"}}
			if change == "before-observation" {
				writePlan(changed)
			}
			if change == "canceled-before" {
				cancel()
			}
			observations := 0
			err := m.settleNFQWS2BootHookStop(ctx, plan, j, func() error {
				observations++
				switch change {
				case "during-observation":
					writePlan(changed)
				case "missing-plan":
					return j.root.Remove("latest-committed-plan.json")
				case "manager-root":
					m.StateRoot = t.TempDir()
				case "canceled-during":
					cancel()
				}
				return nil
			})
			if change == "unchanged" {
				if err != nil || observations != 1 {
					t.Fatal("original plan and fresh absence were refused", err, observations)
				}
				_, record, err := readNFQWS2BootHookJournal(j.root)
				if err != nil || record.State != "stopped" || record.Effects[0].State != "unknown" {
					t.Fatal("stopped evidence lost original history", record, err)
				}
				if err := New(j.path).CheckNFQWS2BootHookRecovery(); err != nil {
					t.Fatal("new manager cannot read verified Stop", err)
				}
				return
			}
			want := ErrReviewChanged
			if strings.HasPrefix(change, "canceled-") {
				want = context.Canceled
			}
			if !errors.Is(err, want) {
				t.Fatal("changed Stop review accepted", err)
			}
			wantObservations := 1
			if change == "before-observation" || change == "canceled-before" {
				wantObservations = 0
			}
			if observations != wantObservations {
				t.Fatal("unexpected fresh absence calls", observations)
			}
			if raw, _, err := readNFQWS2BootHookEvidence(j.root); err != nil || string(raw) != before {
				t.Fatal("refused settlement changed original evidence", err)
			}
			if err := New(j.path).CheckNFQWS2BootHookRecovery(); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("refused Stop no longer fences restart", err)
			}
		})
	}
}

func TestNFQWS2BootHookStopRefusesReplacedStateDirectory(t *testing.T) {
	j := bootStopWAL(t)
	before := string(j.image)
	old := j.path + "-original"
	err := j.settleStopped(func() error {
		if err := os.Rename(j.path, old); err != nil {
			return err
		}
		t.Cleanup(func() { _ = os.RemoveAll(old) })
		if err := os.Mkdir(j.path, 0700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(j.path, nfqws2BootHookJournal), j.image, 0600)
	})
	if !errors.Is(err, ErrReviewChanged) {
		t.Fatal("replaced directory with identical journal accepted", err)
	}
	for _, path := range []string{j.path, old} {
		raw, err := os.ReadFile(filepath.Join(path, nfqws2BootHookJournal))
		if err != nil || string(raw) != before {
			t.Fatal("directory replacement changed journal evidence", path, err)
		}
	}
}
