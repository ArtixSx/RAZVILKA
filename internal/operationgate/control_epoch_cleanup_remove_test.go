package operationgate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestControlCleanupRemoveKeepsOriginalRoleAfterStop(t *testing.T) {
	_, original, review, root := epochReviewFixture(t)
	cleanup, err := review.ReviewExclusiveCleanup(original)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "owned")
	if err := os.WriteFile(path, []byte("known exact writer image"), 0600); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	before, err := held.Stat()
	if err != nil {
		t.Fatal(err)
	}
	// This test exercises the control leaf, not a file ownership issuer.
	// Windows ordinary handles deny deletion; the caller's real held-FD
	// comparison is covered by the Linux sidecar writer tests.
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := RequestSelfUpdateStop(context.Background(), root, controlTestID, 7); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	forward, cancelForward := context.WithTimeout(original, time.Second)
	defer cancelForward()
	named, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, named) {
		t.Fatal(err)
	}
	if err := review.WithRemove(forward, func() error { t.Fatal("Stop granted forward removal"); return nil }); !errors.Is(err, ErrSelfUpdateStopped) {
		t.Fatal(err)
	}
	if err := review.WithCleanupRemove(ctx, cleanup, func() error { return os.Remove(path) }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := review.WithStart(forward, func() error { t.Fatal("cleanup restored Start authority"); return nil }); !errors.Is(err, ErrSelfUpdateStopped) {
		t.Fatal(err)
	}
}

func TestControlCleanupRemoveRefusesForeignCopiedReleasedCancelledAndUnbounded(t *testing.T) {
	for _, change := range []string{"foreign", "copy-control", "copy-cleanup", "released", "cancelled", "unbounded", "closed"} {
		t.Run(change, func(t *testing.T) {
			g, original, review, _ := epochReviewFixture(t)
			cleanup, err := g.ReviewExclusiveCleanup(original)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			switch change {
			case "foreign", "released":
				other := &Gate{}
				held, release, err := other.ExclusiveContext(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
				cleanup, err = other.ReviewExclusiveCleanup(held)
				if err != nil {
					t.Fatal(err)
				}
				if change == "released" {
					release()
				}
			case "copy-control":
				review = &ControlEpochReview{self: review.self, gate: review.gate, dir: review.dir, lock: review.lock, info: review.info, ref: review.ref}
			case "copy-cleanup":
				cleanup = &ExclusiveCleanupReview{self: cleanup.self, owner: cleanup.owner}
			case "cancelled":
				cancel()
			case "unbounded":
				ctx = context.Background()
			case "closed":
				_ = review.Close()
			}
			if err := review.WithCleanupRemove(ctx, cleanup, func() error { t.Fatal("invalid owner reached removal syscall"); return nil }); err == nil {
				t.Fatal("invalid cleanup admitted")
			}
		})
	}
}

func TestControlCleanupRemoveSerializesOnlyTheShortLeafWithStop(t *testing.T) {
	_, original, review, root := epochReviewFixture(t)
	cleanup, err := review.ReviewExclusiveCleanup(original)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	removed := make(chan error, 1)
	go func() {
		removed <- review.WithCleanupRemove(ctx, cleanup, func() error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	stopped := make(chan error, 1)
	go func() { _, err := RequestSelfUpdateStop(ctx, root, controlTestID, 7); stopped <- err }()
	select {
	case err := <-stopped:
		close(release)
		t.Fatal("Stop crossed an in-flight admitted leaf", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	// Expensive caller cleanup takes place after the method has returned; it
	// cannot retain the marker lock or keep later Stop requests waiting.
	if err := review.ObserveCurrent(ctx); !errors.Is(err, ErrSelfUpdateStopped) {
		t.Fatal(err)
	}
}

func TestControlCleanupRemoveReleasedSameGateNeedsFreshActualBorrower(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "control")
	if _, err := InitializeSelfUpdateControl(ctx, path); err != nil {
		t.Fatal(err)
	}
	g := &Gate{}
	held, release, err := g.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	review, err := g.ReviewControlEpoch(held, path)
	if err != nil {
		t.Fatal(err)
	}
	defer review.Close()
	old, err := g.ReviewExclusiveCleanup(held)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err := review.WithCleanupRemove(ctx, old, func() error { t.Fatal("released same-Gate borrower reached syscall"); return nil }); err == nil {
		t.Fatal("released same-Gate cleanup accepted")
	}
	freshHeld, releaseFresh, err := g.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseFresh()
	fresh, err := g.ReviewExclusiveCleanup(freshHeld)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("actual removal syscall failure")
	if err := review.WithCleanupRemove(ctx, fresh, func() error { return failure }); !errors.Is(err, failure) {
		t.Fatal("original syscall error lost", err)
	}
	called := false
	if err := review.WithCleanupRemove(ctx, fresh, func() error { called = true; return nil }); err != nil || !called {
		t.Fatal("fresh same-Gate original cleanup refused", err)
	}
}
