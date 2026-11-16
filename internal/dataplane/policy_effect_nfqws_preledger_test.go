package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Reproduces the current recovery gap, without treating missing disk state as
// an authority. The COMMON writer/lock are actual; kernel effects are the
// existing explicit command model. Native process/queue proof is separate.
func TestNFQWSOriginalPreLedgerFailureLosesCleanupCustody(t *testing.T) {
	for _, cutAt := range []string{"guard", "preflight"} {
		t.Run(cutAt, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			refusal := errors.New("original pure pre-ledger refusal")
			publicationAttempts := 0
			f.options.fault = func(point string, _ int) error {
				if point == "nfq-original-before-write" {
					publicationAttempts++
				}
				return nil
			}
			originalGuard, originalPreflight := f.runtime.Guard, f.runtime.Preflight
			if cutAt == "guard" {
				f.runtime.Guard = func(context.Context, int) error { return refusal }
			} else {
				f.runtime.Preflight = func(context.Context) error { return refusal }
			}
			c := &nfqwsPolicyRecovery{index: -1}
			c.self = c
			ctx := context.Background()
			applyErr := applyPolicyEffectsWithOriginalRecovery(ctx, f.runtime, f.plan, f.root, f.options, nil, c)
			if !errors.Is(applyErr, refusal) {
				t.Fatal("did not reach original pre-ledger cut", applyErr)
			}
			if c.session == nil || c.index != -1 || c.publication != 0 || publicationAttempts != 0 || c.renameAttempted || c.entered || c.retained || c.pending != nil || len(f.calls) != 0 {
				t.Fatal("cut crossed publication/effect boundary", c.index, c.publication, publicationAttempts, c.renameAttempted, c.entered, c.retained, len(f.calls))
			}
			if c.session.borrow == nil || c.session.borrow.open || !c.session.borrow.absent {
				t.Fatal("baseline original writer closure/absence state unexpected")
			}
			if _, err := os.Lstat(filepath.Join(f.root, policyAdditionFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unexpected receipt", err)
			}
			f.runtime.Guard, f.runtime.Preflight = originalGuard, originalPreflight
			// Read each complete modeled family effect independently twice. These
			// reads demonstrate reproduction conditions, never grant recovery.
			before := f.inspections
			for pass := 0; pass < 2; pass++ {
				for i := range f.plan.Effects {
					count, err := f.runtime.ExactPresence(ctx, i)
					if err != nil || count != 0 {
						t.Fatal("fresh effect absence failed", pass, i, count, err)
					}
				}
			}
			if f.inspections-before != 2*len(f.plan.Effects) {
				t.Fatal("absence scan incomplete")
			}
			removeErr := f.remove()
			if !errors.Is(removeErr, os.ErrNotExist) || !errors.Is(removeErr, ErrPolicyAdditionReceipt) || len(f.calls) != 0 {
				t.Fatal("baseline gap changed or cleanup issued command", removeErr, len(f.calls))
			}
			t.Logf("baseline cleanup FAIL: original pure %s refusal; publication_attempts=%d publications=%d effects=%d full_absence_passes=2 original_custody_retained=%t receipt_missing=true", cutAt, publicationAttempts, c.publication, len(f.calls), c.retained)
		})
	}
}

func nfqPreLedgerOriginalFixture(t *testing.T, changes ...func(*nfqwsPolicyRecovery)) (*policyEffectFixture, *nfqwsPolicyRecovery, context.Context) {
	t.Helper()
	e, ctx, f := nfqwsActiveCommandPolicyFixture(t)
	e.material.execution, e.material.executionBound = e, true
	e.inventory.reader.Runner = &activePredicateObservationModel{}
	e.binding.activeReadback = e
	e.binding.network = &nfqwsScopedNetworkBinding{provider: e.material.provider, inventory: e.inventory}
	c := &nfqwsPolicyRecovery{execution: e, index: -1}
	c.self = c
	e.partialRecovery = c
	original := f.runtime.Preflight
	cut := errors.New("original pre-ledger preflight")
	f.runtime.Preflight = func(context.Context) error {
		for _, change := range changes {
			change(c)
		}
		return cut
	}
	f.runtime.Runner = nfqwsScopedApplyRunner{base: f, binding: e.binding, scoped: e.resource.Plan(), plan: f.plan, tools: f.runtime.Tools, guard: f.runtime.Guard}
	var err error
	f.runtime, err = newNFQWSActivePreAddRead(e, e.binding, e.resource.Plan(), f.runtime, f.plan, f.root, c)
	if err != nil {
		t.Fatal(err)
	}
	err = applyPolicyEffectsWithOriginalRecovery(ctx, f.runtime, f.plan, f.root, f.options, nil, c)
	if !errors.Is(err, cut) || !c.retained || (len(changes) == 0 && !c.preLedgerArmed()) || len(f.calls) != 0 {
		t.Fatal("original pre-ledger custody missing", err, c.retained, len(f.calls))
	}
	t.Cleanup(c.close)
	f.runtime.Preflight = original
	return f, c, context.WithValue(ctx, policyEffectReceiptBorrowKey{}, c.session.borrow)
}
func nfqPreLedgerModelAbsence(f *policyEffectFixture, ctx context.Context) error {
	for pass := 0; pass < 2; pass++ {
		for i := range f.plan.Effects {
			n, err := f.runtime.ExactPresence(ctx, i)
			if err != nil || n != 0 {
				return errors.Join(ErrPolicyAdditionUnknown, err)
			}
		}
	}
	return ctx.Err()
}
func TestNFQWSPreLedgerOriginalWriterPublishesOnlyPlannedAndClosesStrictly(t *testing.T) {
	f, c, ctx := nfqPreLedgerOriginalFixture(t)
	verify := func() error { return nfqPreLedgerModelAbsence(f, ctx) }
	if err := c.settlePreLedger(ctx, verify); err != nil {
		t.Fatal(err)
	}
	if !c.settled || c.preLedger.phase != nfqPreLedgerSettled || c.publication != 1 || len(f.calls) != 0 || c.session.status().Unknown || !c.session.status().Removed {
		t.Fatal("unissued plan publication incorrect")
	}
	for _, step := range c.session.doc.Steps {
		if step.State != "planned" {
			t.Fatal("effect state fabricated", step.State)
		}
	}
	if err := c.session.removeKnownEffects(ctx, f.runtime); err != nil || len(f.calls) != 0 {
		t.Fatal("strict cleanup issued a command", err, len(f.calls))
	}
	c.close()
	if err := f.remove(); err != nil || len(f.calls) != 0 {
		t.Fatal("cold strict receipt verification failed", err)
	}
	if err := f.apply(); !errors.Is(err, ErrPolicyAdditionExists) {
		t.Fatal("old generation replayed", err)
	}
}
func TestNFQWSPreLedgerRefusesForeignOrLostOriginalWitness(t *testing.T) {
	for _, cut := range []string{"copy", "rebind", "borrow-close", "writer-close", "marker", "receipt-before", "receipt-during", "cancel", "rules", "process", "queue"} {
		t.Run(cut, func(t *testing.T) {
			f, original, ctx := nfqPreLedgerOriginalFixture(t)
			c := original
			verify := func() error { return nfqPreLedgerModelAbsence(f, ctx) }
			switch cut {
			case "copy":
				c = &nfqwsPolicyRecovery{self: original, preLedger: original.preLedger, session: original.session, retained: true, index: -1}
			case "rebind":
				c.execution.partialRecovery = &nfqwsPolicyRecovery{}
			case "borrow-close":
				c.session.borrow.close()
			case "writer-close":
				c.session.close()
			case "marker":
				if runtime.GOOS == "windows" {
					t.Skip("Windows mandatory lock prevents actual marker mutation; Linux exercises original held-marker refusal")
				}
				if err := os.WriteFile(filepath.Join(f.root, policyAdditionLock), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "receipt-before":
				if err := os.WriteFile(filepath.Join(f.root, policyAdditionFile), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "receipt-during":
				verify = func() error { return os.WriteFile(filepath.Join(f.root, policyAdditionFile), []byte("foreign"), 0600) }
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "rules":
				f.foreign = true
			case "process", "queue":
				verify = func() error { return ErrNFQWSManagedProcessUnknown }
			}
			if err := c.settlePreLedger(ctx, verify); err == nil || original.publication != 0 || len(f.calls) != 0 {
				t.Fatal("foreign absence manufactured receipt", err, original.publication, len(f.calls))
			}
		})
	}
}
func TestNFQWSPreLedgerPublicationRetainsSameFDAndNeverRearms(t *testing.T) {
	for _, point := range []string{"nfq-original-before-write", "nfq-original-publication", "nfq-original-before-sync", "nfq-original-after-sync"} {
		t.Run(point, func(t *testing.T) {
			f, c, ctx := nfqPreLedgerOriginalFixture(t)
			cut := errors.New(point)
			c.session.options.fault = func(got string, _ int) error {
				if got == point {
					return cut
				}
				return nil
			}
			verify := func() error { return nfqPreLedgerModelAbsence(f, ctx) }
			if err := c.settlePreLedger(ctx, verify); !errors.Is(err, cut) || c.preLedger.phase != nfqPreLedgerPublishing || c.preLedgerArmed() || len(f.calls) != 0 {
				t.Fatal("failed write rearmed/forgot original", err)
			}
			c.session.options.fault = nil
			if point == "nfq-original-before-write" {
				id, checksum := c.session.doc.ID, c.session.doc.Checksum
				if c.session.borrow.absent || !c.retained || c.renameAttempted || c.fenced {
					t.Fatal("known pre-write phase/custody lost")
				}
				if err := c.settlePreLedger(ctx, verify); err != nil || c.publication != 1 || !c.settled || c.session.doc.ID != id || c.session.doc.Checksum != checksum {
					t.Fatal("known-noattempt retry changed original doc", err)
				}
				return
			}
			file := c.pending
			if file == nil {
				file = c.session.borrow.published
			}
			if file == nil {
				t.Fatal("actual returned FD lost")
			}
			before, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if err := c.settlePreLedger(ctx, verify); err != nil || c.publication != 1 || !c.settled {
				t.Fatal("bounded same-FD recovery failed", err, c.publication)
			}
			after, err := c.session.borrow.published.Stat()
			if err != nil || !os.SameFile(before, after) || len(f.calls) != 0 {
				t.Fatal("publication rewritten/adopted", err)
			}
		})
	}
}

func TestNFQWSPreLedgerDriftKeepsOriginalWriterFenced(t *testing.T) {
	for _, mode := range []string{"material", "reader", "both-plan", "document"} {
		t.Run(mode, func(t *testing.T) {
			f, c, ctx := nfqPreLedgerOriginalFixture(t, func(c *nfqwsPolicyRecovery) {
				switch mode {
				case "document":
					c.session.doc.Phase = "active"
				case "material":
					c.execution.material = &NFQWSActiveMaterial{}
				case "reader":
					c.preAdd = &nfqws2ActivePreAddRead{}
				case "both-plan":
					c.session.plan.Generation = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
					c.preAdd.runner.plan = c.session.plan
				}
			})
			if !c.retained || !c.fenced || !c.preLedger.borrow.open {
				t.Fatal("original custody dropped after drift")
			}
			if c.settlePreLedger(ctx, func() error { return nil }) == nil || len(f.calls) != 0 {
				t.Fatal("drift admitted settlement")
			}
			original := c.preLedger.borrow
			c.close()
			if original.open {
				t.Fatal("source close leaked original borrowed writer")
			}
		})
	}
}
func TestNFQWSPreLedgerPublishingCannotAdoptForeignPathOrDocument(t *testing.T) {
	for _, mode := range []string{"before-write-foreign", "constructor-doc", "same-bytes-new-inode", "pending-fenced", "changed-doc", "late-rules", "canceled-before-write"} {
		t.Run(mode, func(t *testing.T) {
			f, c, ctx := nfqPreLedgerOriginalFixture(t)
			cut := errors.New("publication cut")
			if mode == "constructor-doc" {
				originalBoot := c.session.options.boot
				c.session.options.boot = func() (string, error) { c.session.doc.Phase = "active"; return originalBoot() }
			}
			point := "nfq-original-before-write"
			if mode == "same-bytes-new-inode" || mode == "pending-fenced" {
				point = "nfq-original-publication"
			}
			var cancel context.CancelFunc
			if mode == "canceled-before-write" {
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
			}
			c.session.options.fault = func(got string, _ int) error {
				if got != point {
					return nil
				}
				if mode == "before-write-foreign" {
					return os.WriteFile(filepath.Join(f.root, policyAdditionFile), []byte("foreign"), 0600)
				}
				if cancel != nil {
					cancel()
				}
				return cut
			}
			verify := func() error { return nfqPreLedgerModelAbsence(f, ctx) }
			if err := c.settlePreLedger(ctx, verify); err == nil {
				t.Fatal("fault did not refuse")
			}
			c.session.options.fault = nil
			switch mode {
			case "before-write-foreign":
				raw, err := os.ReadFile(filepath.Join(f.root, policyAdditionFile))
				if err != nil || string(raw) != "foreign" || c.publication != 0 || c.renameAttempted {
					t.Fatal("foreign receipt overwritten", err)
				}
			case "same-bytes-new-inode":
				if err := c.session.root.WriteAtomic(policyAdditionFile, c.pendingRaw, 0600); err != nil {
					t.Fatal(err)
				}
			case "pending-fenced":
				c.fenced = true
				c.renameAttempted = true
			case "changed-doc":
				c.session.doc.ID = "changed"
			case "late-rules":
				f.foreign = true
			}
			if err := c.settlePreLedger(ctx, verify); err == nil || len(f.calls) != 0 || c.preLedgerArmed() || !c.retained {
				t.Fatal("publication fence relaxed", err, len(f.calls))
			}
		})
	}
}
