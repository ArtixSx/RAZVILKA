package selfupdatejournal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPairedOfflineRetryReceiptFenceAndExactCompletion(t *testing.T) {
	f, ctx, b, _ := pairedJournalFixture(t)
	sealPairedFixture(t, f, ctx, b)
	original, err := os.ReadFile(filepath.Join(f.journal, transaction, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	cut := errors.New("known interrupted offline restore")
	plan := []byte(`{"schema":1,"test":"bounded model; not native image proof"}`)
	run := func(callback func(context.Context, Receipt, []byte, bool, Check, func([]byte) error) error) error {
		return f.store.WithPairedOfflineRetry(ctx, transaction, okay, okay, pairedAdmission, callback)
	}
	err = run(func(c context.Context, r Receipt, data []byte, verifyOnly bool, check Check, bind func([]byte) error) error {
		if c != ctx || len(data) != 0 || r.Schema != PairedSchema {
			t.Fatal("initial binding detached")
		}
		if err := bind(plan); err != nil {
			return err
		}
		if err := check(c); err != nil {
			return err
		}
		return cut
	})
	if !errors.Is(err, cut) {
		t.Fatal("cut lost", err)
	}
	r, present, err := f.store.Current()
	if err != nil || !present || r.Schema != OfflineRetrySchema || !r.Pending() {
		t.Fatal("pending fence absent", err)
	}
	if required, err := f.store.RequiredReadVersion(ctx); err != nil || required != OfflineRetrySchema {
		t.Fatal("reader floor absent", required, err)
	}
	// The exact pre-v5 receipt shape uses strict unknown-field decoding, as does
	// the historical reader. It cannot silently discard the pending binding.
	var legacy struct {
		Schema      int                `json:"schema"`
		ID          string             `json:"id"`
		Phase       string             `json:"phase"`
		Index       int                `json:"index"`
		Command     string             `json:"command,omitempty"`
		Commands    []string           `json:"commands,omitempty"`
		Rollback    bool               `json:"rollback,omitempty"`
		BeforeFiles bool               `json:"before_files,omitempty"`
		Files       []image            `json:"files"`
		Stopped     *StoppedBinding    `json:"stopped,omitempty"`
		Paired      *PairedBinding     `json:"paired,omitempty"`
		Retired     *RetirementBinding `json:"retired,omitempty"`
	}
	pending, _ := os.ReadFile(filepath.Join(f.journal, transaction, "receipt.json"))
	if decode(pending, &legacy) == nil {
		t.Fatal("old strict receipt decoder ignored pending5")
	}
	for _, operation := range []func() error{
		func() error { return f.store.Install(ctx, transaction, okay, okay) },
		func() error { return f.store.Restore(ctx, transaction, okay, okay) },
		func() error { return f.store.Execute(ctx, transaction, "start-candidate-panel", okay, okay) },
		func() error { return f.store.Accept(ctx, transaction, false, okay, okay) },
	} {
		if !errors.Is(operation(), ErrPending) {
			t.Fatal("pending5 granted ordinary mutation")
		}
	}
	err = run(func(c context.Context, r Receipt, data []byte, verifyOnly bool, check Check, bind func([]byte) error) error {
		encoded, _ := json.Marshal(r)
		if !bytes.Equal(data, plan) || !bytes.Equal(encoded, original) {
			t.Fatal("retry original receipt/plan changed")
		}
		if bind(plan) == nil {
			t.Fatal("bound plan overwritten")
		}
		return check(c)
	})
	if err != nil {
		t.Fatal(err)
	}
	complete, _ := os.ReadFile(filepath.Join(f.journal, transaction, "receipt.json"))
	if !bytes.Equal(original, complete) {
		t.Fatal("terminal publication changed original receipt")
	}
	if decode(complete, &legacy) != nil {
		t.Fatal("terminal receipt incompatible with old shape")
	}
	if data, err := os.ReadFile(filepath.Join(f.journal, transaction, "offline-retry-v1.json")); err != nil || !bytes.Equal(data, plan) {
		t.Fatal("retained plan removed")
	}
	if err := run(func(_ context.Context, _ Receipt, data []byte, verifyOnly bool, _ Check, bind func([]byte) error) error {
		if !verifyOnly || !bytes.Equal(data, plan) || bind(plan) == nil {
			t.Fatal("completed retained stage adopted as mutation authority")
		}
		return nil
	}); err != nil {
		t.Fatal("completed verification refused", err)
	}
}

func TestPairedOfflineRetryRefusesBindingDriftAndLostAuthority(t *testing.T) {
	for _, failure := range []string{"owner", "quiescence", "plan", "original", "phase", "unknown-command", "complete-admission"} {
		t.Run(failure, func(t *testing.T) {
			f, ctx, b, _ := pairedJournalFixture(t)
			sealPairedFixture(t, f, ctx, b)
			original, _, _ := f.store.Current()
			if failure == "unknown-command" {
				original.Phase, original.Command, original.BeforeFiles = "command-started", "quiesce-old-runtime", true
				if err := f.store.writeReceipt(original); err != nil {
					t.Fatal(err)
				}
				called := false
				err := f.store.WithPairedOfflineRetry(ctx, transaction, okay, okay, pairedAdmission, func(context.Context, Receipt, []byte, bool, Check, func([]byte) error) error {
					called = true
					return nil
				})
				if err == nil || called {
					t.Fatal("unknown command adopted")
				}
				return
			}
			cut := errors.New("cut")
			err := f.store.WithPairedOfflineRetry(ctx, transaction, okay, okay, pairedAdmission, func(_ context.Context, _ Receipt, _ []byte, _ bool, _ Check, bind func([]byte) error) error {
				if err := bind([]byte(`{"schema":1}`)); err != nil {
					return err
				}
				return cut
			})
			if !errors.Is(err, cut) {
				t.Fatal(err)
			}
			authority, quiescence := Check(okay), Check(okay)
			admission := Admission(pairedAdmission)
			switch failure {
			case "owner":
				authority = func(context.Context) error { return cut }
			case "quiescence":
				quiescence = func(context.Context) error { return cut }
			case "plan":
				if err := os.WriteFile(filepath.Join(f.journal, transaction, "offline-retry-v1.json"), []byte(`{"schema":2}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "original", "phase":
				r, _, _ := f.store.Current()
				if failure == "original" {
					r.Offline.OriginalSHA256 = string(bytes.Repeat([]byte{'a'}, 64))
				} else {
					r.Offline.OriginalPhase = "command-started"
				}
				if err := f.store.writeReceipt(r); err != nil {
					t.Fatal(err)
				}
			case "complete-admission":
				admission = func(c context.Context, effect string, begin func() error) error {
					if effect == "paired-offline-complete" {
						return cut
					}
					return pairedAdmission(c, effect, begin)
				}
			}
			called := false
			err = f.store.WithPairedOfflineRetry(ctx, transaction, authority, quiescence, admission, func(c context.Context, _ Receipt, _ []byte, _ bool, check Check, _ func([]byte) error) error {
				called = true
				return check(c)
			})
			if err == nil || called != (failure == "complete-admission") {
				t.Fatal("invalid retry admitted", called, err)
			}
			if failure == "complete-admission" {
				r, _, err := f.store.Current()
				if err != nil || r.Schema != OfflineRetrySchema {
					t.Fatal("failed terminal publication dropped fence", err)
				}
			}
		})
	}
}

func TestPairedOfflineRetryPlanPublicationWithoutFenceHasNoResumeAuthority(t *testing.T) {
	f, ctx, b, _ := pairedJournalFixture(t)
	sealPairedFixture(t, f, ctx, b)
	before, _, _ := f.store.Current()
	cut := errors.New("before pending receipt")
	err := f.store.WithPairedOfflineRetry(ctx, transaction, okay, okay, func(c context.Context, effect string, begin func() error) error {
		if effect == "paired-offline-pending" {
			return cut
		}
		return pairedAdmission(c, effect, begin)
	}, func(_ context.Context, _ Receipt, _ []byte, _ bool, _ Check, bind func([]byte) error) error {
		return bind([]byte(`{"schema":1}`))
	})
	if !errors.Is(err, cut) {
		t.Fatal(err)
	}
	after, _, err := f.store.Current()
	if err != nil || receiptSHA(before) != receiptSHA(after) {
		t.Fatal("unbound stage changed original receipt", err)
	}
	err = f.store.WithPairedOfflineRetry(ctx, transaction, okay, okay, func(context.Context, string, func() error) error {
		t.Fatal("unbound plan supplied receipt mutation authority")
		return nil
	}, func(_ context.Context, _ Receipt, data []byte, verifyOnly bool, _ Check, bind func([]byte) error) error {
		if !verifyOnly || len(data) == 0 || bind(data) == nil {
			t.Fatal("plan-only cut supplied resume authority")
		}
		return cut
	})
	if !errors.Is(err, cut) {
		t.Fatal(err)
	}
}
