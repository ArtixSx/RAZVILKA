package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ArtixSx/razvilka/internal/components"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNFQWS2CandidateHookJournalWriteAheadAndNoReplay(t *testing.T) {
	root := t.TempDir()
	plan := Plan{PlanID: "dp-1111111111111111", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	j, err := newNFQWS2CandidateHookJournal(root, plan, "original-running-receipt")
	if err != nil {
		t.Fatal(err)
	}
	defer j.root.Close()
	command := NFQWS2HookCommand{Family: 4, Args: []string{"-t", "mangle", "-N", "nfqws_post"}}
	for _, state := range []string{"pending", "acknowledged"} {
		if err := j.effect(command, state); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(root, nfqws2CandidateHooksJournal))
		if err != nil {
			t.Fatal(err)
		}
		var doc nfqws2CandidateHookRecord
		if json.Unmarshal(raw, &doc) != nil || doc.Effects[0].State != state || !reflect.DeepEqual(doc.Effects[0].Command, command) {
			t.Fatal("effect journal not durable")
		}
	}
	if err := j.finish("settled"); err != nil {
		t.Fatal(err)
	}
	if _, err := newNFQWS2CandidateHookJournal(root, plan, "new"); err == nil {
		t.Fatal("existing settlement replayed")
	}
	if err := os.WriteFile(filepath.Join(root, nfqws2CandidateHooksJournal), []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := j.effect(command, "pending"); err == nil {
		t.Fatal("foreign journal replacement accepted")
	}
}

func TestNFQWS2CandidateHookJournalUnknownCannotSettle(t *testing.T) {
	j, err := newNFQWS2CandidateHookJournal(t.TempDir(), Plan{}, "receipt")
	if err != nil {
		t.Fatal(err)
	}
	defer j.root.Close()
	command := NFQWS2HookCommand{Family: 4, Args: []string{"-t", "mangle", "-N", "nfqws_post"}}
	if err := j.effect(command, "pending"); err != nil {
		t.Fatal(err)
	}
	if err := j.effect(command, "unknown"); err != nil {
		t.Fatal(err)
	}
	if err := j.finish("settled"); err == nil {
		t.Fatal("unknown outcome certified settled")
	}
	if err := j.effect(command, "pending"); err == nil {
		t.Fatal("unknown command replayed")
	}
}

func TestNFQWS2CandidateHookEffectsPreAndPostCommandJournalFailure(t *testing.T) {
	for _, mode := range []string{"before", "after", "unknown", "committed-nil"} {
		t.Run(mode, func(t *testing.T) {
			a, _, root := newOwnedNFQWS2(t)
			transaction := stageOwnedNFQWS2(t, a, root, "old.example")
			if err := a.Activate(context.Background(), Plan{}, transaction); err != nil {
				t.Fatal(err)
			}
			lease, err := a.readLease()
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			a.Runner = nfqws2RunFunc(func(context.Context, string, ...string) ([]byte, error) {
				calls++
				if mode == "unknown" {
					return nil, errors.New("ambiguous write")
				}
				return nil, nil
			})
			attempt := &nfqws2HookAttempt{a: a, lease: lease, review: func(context.Context) error { return nil }, source: nfqws2HookSource{iptables: "iptables"}, attempted: map[int][]BackendInventoryRow{}}
			var states []string
			if mode != "committed-nil" {
				attempt.effect = func(_ NFQWS2HookCommand, state string) error {
					states = append(states, state)
					if mode == "before" && state == "pending" || mode == "after" && state == "acknowledged" {
						return errors.New("journal failed")
					}
					return nil
				}
			}
			_, err = attempt.execTable(context.Background(), 4, "mangle", "-N", "nfqws_post")
			switch mode {
			case "before":
				if err == nil || calls != 0 || len(attempt.attempted[4]) != 0 {
					t.Fatal("effect before durable intent")
				}
			case "after":
				if err == nil || calls != 1 || len(attempt.attempted[4]) != 1 {
					t.Fatal("acknowledged effect lost cleanup receipt")
				}
			case "unknown":
				if err == nil || calls != 1 || len(attempt.unacknowledged) != 1 || !reflect.DeepEqual(states, []string{"pending", "unknown"}) {
					t.Fatal("unknown outcome erased or replayed")
				}
			case "committed-nil":
				if err != nil || calls != 1 || len(attempt.attempted[4]) != 1 {
					t.Fatal("original nil-hook semantics changed")
				}
			}
		})
	}
}

func TestNFQWS2CandidateBorrowedReviewIdentityRefusesBeforeEffects(t *testing.T) {
	retained := &components.StockNFQWSNativeReview{}
	replacement := &components.StockNFQWSNativeReview{}
	for _, which := range []string{"root", "pointer", "missing"} {
		t.Run(which, func(t *testing.T) {
			a := &NFQWS2Adapter{firstStartReview: retained, firstStartReviewRoot: "original"}
			attempt := &nfqws2HookAttempt{a: a, lease: &nfqws2Lease{Transaction: "original"}, native: retained, borrowedNative: true}
			switch which {
			case "root":
				a.firstStartReviewRoot = "other"
			case "pointer":
				a.firstStartReview = replacement
			case "missing":
				a.firstStartReview = nil
			}
			before := a.firstStartReview
			if err := attempt.guard(context.Background()); err == nil {
				t.Fatal("mismatched native review accepted")
			}
			if a.firstStartReview != before || attempt.native != retained {
				t.Fatal("refusal changed native ownership")
			}
		})
	}
}

func TestNFQWS2CandidatePendingJournalRechecksAuthorityBeforeCommand(t *testing.T) {
	for _, mode := range []string{"stop", "pointer", "root"} {
		t.Run(mode, func(t *testing.T) {
			a, _, root := newOwnedNFQWS2(t)
			transaction := stageOwnedNFQWS2(t, a, root, "old.example")
			if err := a.Activate(context.Background(), Plan{}, transaction); err != nil {
				t.Fatal(err)
			}
			lease, err := a.readLease()
			if err != nil {
				t.Fatal(err)
			}
			original := &components.StockNFQWSNativeReview{}
			a.firstStartReview, a.firstStartReviewRoot = original, lease.Transaction
			revoked := false
			calls := 0
			a.Runner = nfqws2RunFunc(func(context.Context, string, ...string) ([]byte, error) { calls++; return nil, nil })
			j, err := newNFQWS2CandidateHookJournal(t.TempDir(), Plan{}, "original")
			if err != nil {
				t.Fatal(err)
			}
			defer j.root.Close()
			attempt := &nfqws2HookAttempt{a: a, lease: lease, native: original, borrowedNative: true, review: func(context.Context) error {
				if revoked {
					return ErrReviewChanged
				}
				return nil
			}, source: nfqws2HookSource{iptables: "iptables"}, attempted: map[int][]BackendInventoryRow{}}
			attempt.effect = func(command NFQWS2HookCommand, state string) error {
				if err := j.effect(command, state); err != nil {
					return err
				}
				if state == "pending" {
					switch mode {
					case "stop":
						revoked = true
					case "pointer":
						a.firstStartReview = &components.StockNFQWSNativeReview{}
					case "root":
						a.firstStartReviewRoot = "other"
					}
				}
				return nil
			}
			reason, err := attempt.execTable(context.Background(), 4, "mangle", "-N", "nfqws_post")
			if err == nil || reason != NFQWS2HookReasonGuard || calls != 0 || len(attempt.attempted[4]) != 0 || len(attempt.unacknowledged) != 0 {
				t.Fatal("command escaped post-journal authority guard")
			}
			if len(j.record.Effects) != 1 || j.record.Effects[0].State != "pending" {
				t.Fatal("durable pending evidence was lost")
			}
			if attempt.native != original {
				t.Fatal("refusal changed original cleanup owner")
			}
		})
	}
}

func TestNFQWS2CandidateSettlementRollbackRetryPhaseIsExact(t *testing.T) {
	for _, mode := range []string{"nfq-settle", "nfq-unknown", "sing-settle", "nfq-activate"} {
		t.Run(mode, func(t *testing.T) {
			m, _, plan, e := rollbackRetryFixture(t)
			previous, exists, err := m.Committed()
			if err != nil || !exists {
				t.Fatal(err)
			}
			adapter := "nfqws2"
			phase := "settle-hooks"
			if mode == "sing-settle" {
				adapter = "sing-box"
			}
			if mode == "nfq-unknown" {
				phase = "settle-hooks-unknown"
			}
			if mode == "nfq-activate" {
				phase = "activate"
			}
			if adapter == "nfqws2" {
				if err := m.Register(&fakeAdapter{id: adapter}); err != nil {
					t.Fatal(err)
				}
			}
			plan.Adapters, previous.Adapters = []string{adapter}, []string{adapter}
			var steps []ExecutionStep
			for _, step := range e.Steps {
				if step.Phase == "health" {
					continue
				}
				step.Adapter = adapter
				if step.Phase == "commit-adapter" {
					step.Phase = phase
				}
				steps = append(steps, step)
			}
			e.Steps = steps
			_, ok := m.reviewFailedRollbackImages(plan.PlanID, plan.Digest, &e, &e, plan, previous)
			want := mode == "nfq-settle" || mode == "nfq-activate"
			if ok != want {
				t.Fatalf("phase boundary mode=%s accepted=%v want=%v", mode, ok, want)
			}
		})
	}
}
