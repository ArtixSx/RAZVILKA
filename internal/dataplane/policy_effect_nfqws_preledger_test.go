package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
