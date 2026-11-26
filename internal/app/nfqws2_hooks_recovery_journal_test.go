package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestNFQWS2HookBootJournalFencesLiveAdmissionAndOfflineStop(t *testing.T) {
	a, _, _ := nfqws2HookAppFixture(t)
	if err := a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(a.Dataplane.StateRoot, "nfqws2-boot-hooks.json")
	evidence := []byte(`{"state":"pending"}`)
	if err := os.WriteFile(path, evidence, 0600); err != nil {
		t.Fatal(err)
	}
	_, release, err := a.Operations.ExclusiveContext(context.Background())
	if err == nil {
		release()
		t.Fatal("live admission bypassed malformed boot journal")
	}
	settle, closeReview, err := ReviewNFQWS2HookStop(context.Background(), a.Dataplane, filepath.Join(a.Dataplane.StateRoot, "config.json"))
	if err == nil || settle != nil || closeReview != nil {
		t.Fatal("offline Stop bypassed malformed boot journal", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != string(evidence) {
		t.Fatal("refusal changed evidence", err)
	}
}

func TestNFQWS2HookJournalSuccessAndKnownFailureSettle(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "known-failure"}[failure], func(t *testing.T) {
			a, _, model := nfqws2HookAppFixture(t)
			if err := a.InitializeComponentRecoveryGate(); err != nil {
				t.Fatal(err)
			}
			model.restore = func(ctx context.Context, p dataplane.Plan) (dataplane.NFQWS2HookRestore, error) {
				if !errors.Is(CheckNFQWS2HookRecovery(a.Dataplane.StateRoot), ErrNFQWS2HookRecovery) {
					t.Fatal("intent not durable before effect")
				}
				// The real guard must remain usable under the SAME exclusive admission.
				if err := a.nfqws2HookGuard(a.Store.Get())(ctx); err != nil {
					t.Fatal("self marker denied original guard", err)
				}
				if failure {
					return dataplane.NFQWS2HookRestore{Instance: model.instance, RolledBack: true}, dataplane.ErrNFQWS2HookRestore
				}
				return dataplane.NFQWS2HookRestore{Instance: model.instance, Restored: []int{4}}, nil
			}
			err := a.restoreNFQWS2HooksRound(context.Background(), time.Now())
			if (err != nil) != failure {
				t.Fatal(err)
			}
			if err := CheckNFQWS2HookRecovery(a.Dataplane.StateRoot); err != nil {
				t.Fatal(err)
			}
			_, release, err := a.Operations.ExclusiveContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			release()
		})
	}
}
func TestNFQWS2HookJournalCrashAndUncertainRetainedOnRestart(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "crash-before-completion", true: "uncertain"}[uncertain], func(t *testing.T) {
			a, p, model := nfqws2HookAppFixture(t)
			if uncertain {
				model.restore = func(context.Context, dataplane.Plan) (dataplane.NFQWS2HookRestore, error) {
					return dataplane.NFQWS2HookRestore{Uncertain: true}, dataplane.ErrNFQWS2HookUncertain
				}
				if err := a.restoreNFQWS2HooksRound(context.Background(), time.Now()); !errors.Is(err, ErrNFQWS2HookRecovery) {
					t.Fatal(err)
				}
			} else {
				o, err := beginNFQWS2HookJournal(a.Dataplane.StateRoot, p, model.instance)
				if err != nil {
					t.Fatal(err)
				}
				o.root.Close()
			}
			before, err := os.ReadFile(filepath.Join(a.Dataplane.StateRoot, nfqws2HookJournalName))
			if err != nil {
				t.Fatal(err)
			}
			restarted := &App{Dataplane: dataplane.New(a.Dataplane.StateRoot)}
			if err := restarted.InitializeComponentRecoveryGate(); err != nil {
				t.Fatal(err)
			}
			_, release, err := restarted.Operations.ExclusiveContext(context.Background())
			if err == nil {
				release()
				t.Fatal("restart reopened admission")
			}
			if !errors.Is(err, ErrNFQWS2HookRecovery) {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(filepath.Join(a.Dataplane.StateRoot, nfqws2HookJournalName))
			if string(before) != string(after) {
				t.Fatal("startup changed marker")
			}
		})
	}
}
func TestNFQWS2HookOfflineStopSettlementRequiresFreshAbsenceAndCAS(t *testing.T) {
	a, p, m := nfqws2HookAppFixture(t)
	o, err := beginNFQWS2HookJournal(a.Dataplane.StateRoot, p, m.instance)
	if err != nil {
		t.Fatal(err)
	}
	defer o.root.Close()
	calls := 0
	inactive := false
	settle := nfqws2HookStopSettlement(context.Background(), a.Dataplane, o, func() error {
		calls++
		if !inactive {
			return dataplane.ErrRuntimeInactivity
		}
		return nil
	})
	if err := settle(); !errors.Is(err, ErrNFQWS2HookRecovery) {
		t.Fatal(err)
	}
	if CheckNFQWS2HookRecovery(a.Dataplane.StateRoot) == nil {
		t.Fatal("absence failure settled")
	}
	inactive = true
	if err := settle(); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || CheckNFQWS2HookRecovery(a.Dataplane.StateRoot) != nil {
		t.Fatal("verified offline Stop did not settle")
	}
	// A stale cleanup cannot settle a later recovery intent.
	newer, err := beginNFQWS2HookJournal(a.Dataplane.StateRoot, p, "new-instance")
	if err != nil {
		t.Fatal(err)
	}
	defer newer.root.Close()
	if err := settle(); !errors.Is(err, ErrNFQWS2HookRecovery) {
		t.Fatal("stale cleanup overwrote journal", err)
	}
}
func TestNFQWS2HookJournalUnsafeMarkerPreventsEffects(t *testing.T) {
	a, _, m := nfqws2HookAppFixture(t)
	path := filepath.Join(a.Dataplane.StateRoot, nfqws2HookJournalName)
	// A directory is invalid on all supported hosts, before a single effect.
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := a.restoreNFQWS2HooksRound(context.Background(), time.Now()); !errors.Is(err, ErrNFQWS2HookRecovery) {
		t.Fatal(err)
	}
	if m.restored != 0 {
		t.Fatal("effects before durable intent")
	}
	_, release, err := a.Operations.ExclusiveContext(context.Background())
	if err == nil {
		release()
		t.Fatal("durability failure did not fence")
	}
}

func TestNFQWS2HookOfflineStopAdmissionLossOnly(t *testing.T) {
	for _, class := range []string{dataplane.NFQWS2HooksLoss, dataplane.NFQWS2HooksFull, dataplane.NFQWS2HooksOther} {
		t.Run(class, func(t *testing.T) {
			a, p, m := nfqws2HookAppFixture(t)
			o, err := beginNFQWS2HookJournal(a.Dataplane.StateRoot, p, m.instance)
			if err != nil {
				t.Fatal(err)
			}
			defer o.root.Close()
			inactive := false
			err = nfqws2HookStopAdmission(o.record, func() error { return dataplane.ErrRuntimeInactivity }, func() (dataplane.NFQWS2HookRestore, error) {
				return dataplane.NFQWS2HookRestore{Class: class, Instance: m.instance, Families: []dataplane.NFQWS2HookFamilyState{{Family: 4, Class: class}}}, nil
			})
			if class != dataplane.NFQWS2HooksLoss {
				if !errors.Is(err, ErrNFQWS2HookRecovery) {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// Original Stop succeeds, and only a new full absence proof settles.
			inactive = true
			settle := nfqws2HookStopSettlement(context.Background(), a.Dataplane, o, func() error {
				if !inactive {
					return dataplane.ErrRuntimeInactivity
				}
				return nil
			})
			if err := settle(); err != nil {
				t.Fatal(err)
			}
			if CheckNFQWS2HookRecovery(a.Dataplane.StateRoot) != nil {
				t.Fatal("LOSS recovery remained fenced")
			}
		})
	}
	j := nfqws2HookJournal{Instance: "original"}
	if err := nfqws2HookStopAdmission(j, func() error { return dataplane.ErrRuntimeInactivity }, func() (dataplane.NFQWS2HookRestore, error) {
		return dataplane.NFQWS2HookRestore{Class: dataplane.NFQWS2HooksLoss, Instance: "replacement"}, nil
	}); err == nil {
		t.Fatal("replacement receipt admitted")
	}
}

func TestNFQWS2HookJournalDirectorySyncFailureRetainsPending(t *testing.T) {
	a, p, m := nfqws2HookAppFixture(t)
	r, err := openNFQWS2HookJournal(a.Dataplane.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	syncErr := errors.New("modeled directory fsync failure")
	_, err = writeNFQWS2HookJournalWithSync(r, nfqws2HookJournal{Version: 1, State: "pending", Reason: "repair-in-progress", Plan: p, Instance: m.instance, Started: time.Now().UTC()}, func() error { return syncErr })
	if !errors.Is(err, syncErr) {
		t.Fatal("fsync failure ignored", err)
	}
	if !errors.Is(CheckNFQWS2HookRecovery(a.Dataplane.StateRoot), ErrNFQWS2HookRecovery) {
		t.Fatal("failed sync reopened admission")
	}
}

func TestNFQWS2HookOfflineStopRefusesMixedOrMissingFamilyLoss(t *testing.T) {
	for _, families := range [][]dataplane.NFQWS2HookFamilyState{
		nil,
		{{Family: 4, Class: dataplane.NFQWS2HooksFull}, {Family: 6, Class: dataplane.NFQWS2HooksLoss}},
		{{Family: 4, Class: dataplane.NFQWS2HooksLoss}, {Family: 6, Class: dataplane.NFQWS2HooksFull}},
		{{Family: 4, Class: dataplane.NFQWS2HooksLoss}, {Family: 4, Class: dataplane.NFQWS2HooksLoss}},
		{{Family: 6, Class: dataplane.NFQWS2HooksLoss}},
	} {
		err := nfqws2HookStopAdmission(nfqws2HookJournal{Instance: "original"}, func() error { return dataplane.ErrRuntimeInactivity }, func() (dataplane.NFQWS2HookRestore, error) {
			return dataplane.NFQWS2HookRestore{Class: dataplane.NFQWS2HooksLoss, Instance: "original", Families: families}, nil
		})
		if !errors.Is(err, ErrNFQWS2HookRecovery) {
			t.Fatal("incomplete/mixed family loss admitted", families, err)
		}
	}
}
