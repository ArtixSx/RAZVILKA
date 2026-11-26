package operationgate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestControlEpochCleanupIsCapturedBeforeStopAndCannotReviveForwardUse(t *testing.T) {
	g, original, review, root := epochReviewFixture(t)
	ctx, cancel := context.WithCancel(original)
	cleanup, err := review.ReviewExclusiveCleanup(ctx)
	if err != nil {
		t.Fatal("actual original cleanup capture", err)
	}
	if _, err := RequestSelfUpdateStop(context.Background(), root, controlTestID, 7); err != nil {
		t.Fatal(err)
	}
	if _, err := review.ReviewExclusiveCleanup(original); !errors.Is(err, ErrSelfUpdateStopped) {
		t.Fatal("cleanup issued after Stop", err)
	}
	cancel()
	g.FenceJournal()
	bounded, finish := context.WithTimeout(context.Background(), time.Second)
	defer finish()
	called := false
	if err := cleanup.WithCurrent(bounded, func() error { called = true; return review.CurrentForCleanup(bounded) }); err != nil || !called {
		t.Fatal("Stop/cancel discarded the original still-held cleanup lifetime", err)
	}
	if err := review.WithRename(bounded, func() error { t.Fatal("cleanup context authorized forward publication"); return nil }); !errors.Is(err, ErrBusy) {
		t.Fatal("cleanup review manufactured forward admission", err)
	}
	if g.Snapshot().Active != 1 {
		t.Fatal("cleanup capture/use released original operation before actual join")
	}
}

func TestControlEpochCleanupComparisonRefusesUnboundedCancelledCopiedClosedAndMarkerDrift(t *testing.T) {
	for _, change := range []string{"unbounded", "cancelled", "copy", "closed", "marker"} {
		t.Run(change, func(t *testing.T) {
			_, _, review, root := epochReviewFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			switch change {
			case "unbounded":
				ctx = context.Background()
			case "cancelled":
				cancel()
			case "copy":
				review = &ControlEpochReview{self: review.self, gate: review.gate, dir: review.dir, lock: review.lock, info: review.info, ref: review.ref}
			case "closed":
				_ = review.Close()
			case "marker":
				if err := os.WriteFile(filepath.Join(root, selfControlLock), []byte("foreign marker"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := review.CurrentForCleanup(ctx); err == nil {
				t.Fatal("cleanup comparison accepted invalid retained owner or lifetime")
			}
		})
	}
}

func TestControlEpochCleanupComparisonRefusesAnotherInstallationOrLaterStoppedEpoch(t *testing.T) {
	for _, change := range []string{"installation", "epoch"} {
		t.Run(change, func(t *testing.T) {
			_, _, review, root := epochReviewFixture(t)
			stop, err := RequestSelfUpdateStop(context.Background(), root, controlTestID, 7)
			if err != nil {
				t.Fatal(err)
			}
			if change == "installation" {
				stop.InstallationID = controlOtherID
			} else {
				stop.Sequence++
			}
			d, err := openControlDirectory(root, false)
			if err != nil {
				t.Fatal(err)
			}
			defer d.close()
			// Both records are internally valid and agree; only the original
			// retained installation/epoch comparison can reject them.
			if err := writeControl(d, selfControlCurrent, stop); err != nil {
				t.Fatal(err)
			}
			if err := writeControl(d, controlRequestName(stop), stop); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := review.CurrentForCleanup(ctx); !errors.Is(err, ErrSelfUpdateStopChanged) {
				t.Fatal("cleanup comparison adopted another owner or later epoch", err)
			}
		})
	}
}

func TestControlEpochCleanupRefusesRawCopiedClosedAndCancelledIssuer(t *testing.T) {
	for _, change := range []string{"raw", "copy", "closed", "cancelled"} {
		t.Run(change, func(t *testing.T) {
			_, ctx, review, _ := epochReviewFixture(t)
			switch change {
			case "raw":
				ctx = context.Background()
			case "copy":
				review = &ControlEpochReview{self: review.self, gate: review.gate, dir: review.dir, lock: review.lock, info: review.info, ref: review.ref}
			case "closed":
				_ = review.Close()
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if cleanup, err := review.ReviewExclusiveCleanup(ctx); err == nil || cleanup != nil {
				t.Fatal("unowned or late issuer created cleanup capability", err)
			}
		})
	}
}
