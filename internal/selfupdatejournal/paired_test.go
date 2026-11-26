package selfupdatejournal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These are file lifecycle tests. The archive/native owner checks are modeled
// here; updatecheck tests separately read and hash the actual private archive.
func pairedJournalFixture(t *testing.T) (*fixture, context.Context, PairedBinding, *bool) {
	t.Helper()
	f := preparedPriorFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	r, _, err := f.store.Current()
	if err != nil {
		t.Fatal(err)
	}
	b := PairedBinding{ManifestSHA256: strings.Repeat("a", 64), PreparedSHA256: receiptSHA(r), ReviewSHA256: strings.Repeat("b", 64), InstallationID: strings.Repeat("c", 32), Sequence: 1, Revision: 0}
	validEvidence := true
	f.store.Close()
	f.store, err = OpenWithPairedEvidence(f.installation, f.journal, func(c context.Context, r Receipt, _ string, _ bool) error {
		if c != ctx || !validEvidence || r.Paired == nil || *r.Paired != b {
			return ErrMismatch
		}
		return c.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, ctx, b, &validEvidence
}

func pairedAdmission(ctx context.Context, _ string, rename func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return rename()
}

func sealPairedFixture(t *testing.T, f *fixture, ctx context.Context, b PairedBinding) {
	t.Helper()
	if err := f.store.SealPairedPriorState(ctx, transaction, okay, okay, func(c context.Context, r Receipt) (PairedBinding, error) {
		if c != ctx || receiptSHA(r) != b.PreparedSHA256 {
			t.Fatal("capture detached from prepared owner/source")
		}
		return b, nil
	}, pairedAdmission); err != nil {
		t.Fatal(err)
	}
}

func acceptPairedFixture(t *testing.T, f *fixture, ctx context.Context) {
	t.Helper()
	if err := f.store.Install(ctx, transaction, okay, okay); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Execute(ctx, transaction, "start-candidate-panel", okay, okay); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Accept(ctx, transaction, false, okay, okay); err != nil {
		t.Fatal(err)
	}
}

func TestPairedLifecycleKeepsFleetUntilVerifiedTerminalRetirement(t *testing.T) {
	f, ctx, binding, evidence := pairedJournalFixture(t)
	sealPairedFixture(t, f, ctx, binding)
	r, _, err := f.store.Current()
	if err != nil || r.Schema != 4 || !r.Pending() || r.Paired.Revision != 0 {
		t.Fatal("paired preparation did not retain a revision0 pending fence", err)
	}
	if required, err := f.store.RequiredReadVersion(ctx); err != nil || required != 4 {
		t.Fatal("paired floor not visible", required, err)
	}
	if _, err := f.store.RetainedBinaryImages(ctx); !errors.Is(err, ErrPending) {
		t.Fatal("pending paired state removed controllers", err)
	}
	if err := f.store.RetirePairedPriorState(ctx, transaction, strings.Repeat("d", 64), okay, okay, pairedAdmission); err == nil {
		t.Fatal("copy/prepared metadata manufactured retirement")
	}
	if err := f.store.Restore(ctx, transaction, okay, okay); !errors.Is(err, ErrRetired) {
		t.Fatal("partial six-file rollback admitted for paired state", err)
	}
	acceptPairedFixture(t, f, ctx)
	images, err := f.store.RetainedBinaryImages(ctx)
	if err != nil || len(images) != 2 {
		t.Fatal("accepted but unretired controllers disappeared", err)
	}
	old, _ := os.ReadFile(filepath.Join(f.journal, transaction, "old-0"))
	if err := f.store.RetirePairedPriorState(ctx, transaction, strings.Repeat("d", 64), okay, okay, pairedAdmission); err != nil {
		t.Fatal(err)
	}
	images, err = f.store.RetainedBinaryImages(ctx)
	if err != nil || len(images) != 0 {
		t.Fatal("verified retired recovery set stayed eligible", err)
	}
	retained, err := f.store.RetainedReceipt(ctx, transaction)
	if err != nil || retained.Phase != "archived" || retained.Retired == nil {
		t.Fatal("retirement receipt unavailable", err)
	}
	after, _ := os.ReadFile(filepath.Join(f.journal, transaction, "old-0"))
	if string(old) != string(after) {
		t.Fatal("retirement removed or changed the frozen old binary")
	}
	plain, err := Open(f.installation, f.journal)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if _, err := plain.RetainedBinaryImages(ctx); err == nil {
		t.Fatal("bare metadata/digest supplied an archive grant")
	}
	for _, operation := range []func() error{
		func() error { return f.store.Restore(ctx, transaction, okay, okay) },
		func() error { return f.store.Install(ctx, transaction, okay, okay) },
		func() error { return f.store.Execute(ctx, transaction, "start-rollback-panel", okay, okay) },
		func() error { return f.store.Accept(ctx, transaction, true, okay, okay) },
	} {
		if err := operation(); !errors.Is(err, ErrRetired) {
			t.Fatal("retired state authorized replacement/replay", err)
		}
	}
	*evidence = false
	if _, err := f.store.RetainedBinaryImages(ctx); err == nil {
		t.Fatal("removed/corrupt archive kept supplying eligibility grant")
	}
}

func TestPairedPublicationCutsNeverGrantPendingRetirement(t *testing.T) {
	for _, cut := range []string{"before:receipt:paired-prepared", "after:receipt:paired-prepared", "before:paired-current", "after:paired-current"} {
		t.Run(cut, func(t *testing.T) {
			f, ctx, binding, _ := pairedJournalFixture(t)
			seen := false
			f.store.fault = func(point string) error {
				if point == cut {
					seen = true
					return interrupted
				}
				return nil
			}
			err := f.store.SealPairedPriorState(ctx, transaction, okay, okay, func(context.Context, Receipt) (PairedBinding, error) { return binding, nil }, pairedAdmission)
			if !seen || err == nil {
				t.Fatal("cut not observed", err)
			}
			f.store.fault = nil
			if err := f.store.RetirePairedPriorState(ctx, transaction, strings.Repeat("d", 64), okay, okay, pairedAdmission); err == nil {
				t.Fatal("publication cut granted retirement")
			}
			if _, err := f.store.RetainedBinaryImages(ctx); !errors.Is(err, ErrPending) {
				t.Fatal("cut lost its pending fleet fence", err)
			}
			if cut == "after:receipt:paired-prepared" || cut == "before:paired-current" {
				if err := f.store.Install(ctx, transaction, okay, okay); err == nil {
					t.Fatal("receipt/pointer cut authorized installation")
				}
			}
		})
	}
}

func TestPairedRetirementCutsAndRefusalsPreserveEvidence(t *testing.T) {
	for _, change := range []string{"authority", "terminal", "archive", "skip-rename", "before:receipt:archived", "after:receipt:archived"} {
		t.Run(change, func(t *testing.T) {
			f, ctx, binding, evidence := pairedJournalFixture(t)
			sealPairedFixture(t, f, ctx, binding)
			acceptPairedFixture(t, f, ctx)
			authority, terminal, admission := okay, okay, Admission(pairedAdmission)
			switch change {
			case "authority":
				authority = func(context.Context) error { return interrupted }
			case "terminal":
				terminal = func(context.Context) error { return interrupted }
			case "archive":
				*evidence = false
			case "skip-rename":
				admission = func(context.Context, string, func() error) error { return nil }
			default:
				f.store.fault = func(point string) error {
					if point == change {
						return interrupted
					}
					return nil
				}
			}
			if err := f.store.RetirePairedPriorState(ctx, transaction, strings.Repeat("d", 64), authority, terminal, admission); err == nil {
				t.Fatal("refusal/cut admitted", change)
			}
			f.store.fault = nil
			*evidence = true
			images, err := f.store.RetainedBinaryImages(ctx)
			retired := change == "after:receipt:archived"
			if err != nil || retired && len(images) != 0 || !retired && len(images) != 2 {
				t.Fatal("cut has inconsistent durable disposition", err)
			}
			if err := f.store.RetirePairedPriorState(ctx, transaction, strings.Repeat("d", 64), okay, okay, pairedAdmission); err != nil {
				t.Fatal("matching data-only retry failed", err)
			}
		})
	}
}
