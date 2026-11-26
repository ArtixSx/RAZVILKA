package operationgate

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestControlCleanupStartUsesOriginalLifetimeAfterCancellationAndStop(t *testing.T) {
	g, original, review, root := epochReviewFixture(t)
	ctx, cancel := context.WithCancel(original)
	cleanup, err := review.ReviewExclusiveCleanup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := RequestSelfUpdateStop(context.Background(), root, controlTestID, 7); err != nil {
		t.Fatal(err)
	}
	g.FenceJournal()
	bounded, finish := context.WithTimeout(context.Background(), time.Second)
	defer finish()
	called := 0
	startErr := errors.New("actual syscall refused")
	if err := review.WithCleanupStart(bounded, cleanup, func() error { called++; return startErr }); !errors.Is(err, startErr) || called != 1 {
		t.Fatal("original cleanup lost after Stop", err, called)
	}
	if err := review.WithStart(bounded, func() error { t.Fatal("cleanup issued forward admission"); return nil }); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
}

func TestControlCleanupStartRefusesForeignCopiedReleasedAndInvalidOwners(t *testing.T) {
	for _, change := range []string{"foreign-gate", "copied-cleanup", "copied-control", "released", "closed", "unbounded", "cancelled"} {
		t.Run(change, func(t *testing.T) {
			g, original, review, root := epochReviewFixture(t)
			cleanup, err := g.ReviewExclusiveCleanup(original)
			if err != nil {
				t.Fatal(err)
			}
			if change == "released" || change == "foreign-gate" {
				other := &Gate{}
				ctx, release, err := other.ExclusiveContext(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				cleanup, err = other.ReviewExclusiveCleanup(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
				if change == "released" {
					review, err = other.ReviewControlEpoch(ctx, root)
					if err != nil {
						t.Fatal(err)
					}
					defer review.Close()
					release()
				}
			}
			bounded, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			switch change {
			case "copied-cleanup":
				cleanup = &ExclusiveCleanupReview{self: cleanup.self, owner: cleanup.owner}
			case "copied-control":
				review = &ControlEpochReview{self: review.self, gate: review.gate, dir: review.dir, lock: review.lock, info: review.info, ref: review.ref}
			case "closed":
				_ = review.Close()
			case "unbounded":
				bounded = context.Background()
			case "cancelled":
				cancel()
			}
			if err := review.WithCleanupStart(bounded, cleanup, func() error { t.Fatal("invalid owner reached Start"); return nil }); err == nil {
				t.Fatal("invalid cleanup/control owner admitted")
			}
		})
	}
}

func TestControlCleanupStartSerializesOnlyBeginWithDurableStop(t *testing.T) {
	_, original, review, root := epochReviewFixture(t)
	cleanup, err := review.ReviewExclusiveCleanup(original)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	entered, finish, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		result <- review.WithCleanupStart(ctx, cleanup, func() error { close(entered); <-finish; return nil })
	}()
	<-entered
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer stopCancel()
	if _, err := RequestSelfUpdateStop(stopCtx, root, controlTestID, 7); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Stop crossed the actual Start leaf", err)
	}
	close(finish)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, err := RequestSelfUpdateStop(ctx, root, controlTestID, 7); err != nil {
		t.Fatal("leaf retained control lock", err)
	}
}
