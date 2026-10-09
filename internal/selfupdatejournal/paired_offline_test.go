package selfupdatejournal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPairedOfflineOwnerKeepsReceiptAndExistingWriter(t *testing.T) {
	f, ctx, binding, _ := pairedJournalFixture(t)
	sealPairedFixture(t, f, ctx, binding)
	before, _ := os.ReadFile(filepath.Join(f.journal, transaction, "receipt.json"))
	marker, err := os.Lstat(filepath.Join(f.journal, ".writer.lock"))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err := f.store.WithPairedOfflineRestore(ctx, transaction, okay, okay, func(c context.Context, r Receipt, check Check) error {
		calls++
		if c != ctx || r.Schema != PairedSchema || check(context.Background()) == nil || check(c) != nil {
			t.Fatal("original owner/writer was detached")
		}
		return nil
	}); err != nil || calls != 1 {
		t.Fatal(err, calls)
	}
	after, _ := os.ReadFile(filepath.Join(f.journal, transaction, "receipt.json"))
	current, _ := os.Lstat(filepath.Join(f.journal, ".writer.lock"))
	if string(before) != string(after) || !os.SameFile(marker, current) {
		t.Fatal("offline use changed receipt/writer identity")
	}
	if err := f.store.Restore(ctx, transaction, okay, okay); !errors.Is(err, ErrRetired) {
		t.Fatal("offline callback opened six-file replay", err)
	}
}

func TestPairedOfflineOwnerRefusesForeignEvidenceEpochAndCuts(t *testing.T) {
	for _, fault := range []string{"evidence", "owner", "quiescence", "callback-cut", "changed-receipt", "writer-rebound"} {
		t.Run(fault, func(t *testing.T) {
			f, ctx, binding, evidence := pairedJournalFixture(t)
			sealPairedFixture(t, f, ctx, binding)
			failure := errors.New("owner/cut")
			authority, quiescence := Check(okay), Check(okay)
			if fault == "evidence" {
				*evidence = false
			}
			if fault == "owner" {
				authority = func(context.Context) error { return failure }
			}
			if fault == "quiescence" {
				quiescence = func(context.Context) error { return failure }
			}
			calls := 0
			err := f.store.WithPairedOfflineRestore(ctx, transaction, authority, quiescence, func(c context.Context, r Receipt, check Check) error {
				calls++
				switch fault {
				case "callback-cut":
					return failure
				case "changed-receipt":
					if err := os.WriteFile(filepath.Join(f.journal, transaction, "receipt.json"), []byte("foreign"), 0600); err != nil {
						t.Fatal(err)
					}
				case "writer-rebound":
					// Windows locks the marker against moving. The denied move
					// itself preserves the held lease and ends this fault attempt.
					path := filepath.Join(f.journal, ".writer.lock")
					if err := os.Rename(path, path+".held"); err != nil {
						return err
					}
					if err := os.WriteFile(path, []byte("foreign"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return check(c)
			})
			if err == nil {
				t.Fatal("unsafe offline callback accepted", fault)
			}
			if (fault == "evidence" || fault == "owner" || fault == "quiescence") && calls != 0 {
				t.Fatal("refusal reached restore callback")
			}
		})
	}
}
