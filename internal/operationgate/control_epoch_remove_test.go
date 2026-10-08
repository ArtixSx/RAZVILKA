package operationgate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestControlEpochRemoveLinearizesActualReceiptRemovalWithStop(t *testing.T) {
	_, original, review, root := epochReviewFixture(t)
	ctx, cancel := context.WithTimeout(original, 2*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "receipt")
	if err := os.WriteFile(path, []byte("actual published receipt"), 0600); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	result := make(chan error, 1)
	go func() {
		result <- review.WithRemove(ctx, func() error {
			close(entered)
			<-release // Test barrier immediately before the actual removal syscall.
			return os.Remove(path)
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("removal not admitted", ctx.Err())
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	_, err := RequestSelfUpdateStop(stopCtx, root, controlTestID, 7)
	stopCancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Stop overlapped admitted removal", err)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("actual receipt was not removed", err)
	}
	var syscallErr error
	if err := review.WithRemove(ctx, func() error { syscallErr = os.Remove(path); return syscallErr }); syscallErr == nil || !errors.Is(err, syscallErr) {
		t.Fatal("actual remove error swallowed", err, syscallErr)
	}
	if _, err := RequestSelfUpdateStop(ctx, root, controlTestID, 7); err != nil {
		t.Fatal("removal kept Stop locked during later readback", err)
	}
	if err := review.WithRemove(ctx, func() error { t.Fatal("removal after Stop"); return nil }); !errors.Is(err, ErrSelfUpdateStopped) {
		t.Fatal("Stop did not fence late removal", err)
	}
}

func TestControlEpochRemoveRefusesUnownedUnboundedCopiedClosedAndDrifted(t *testing.T) {
	for _, change := range []string{"raw", "unbounded", "foreign", "cancelled", "copy", "closed", "marker"} {
		t.Run(change, func(t *testing.T) {
			_, original, review, root := epochReviewFixture(t)
			ctx, cancel := context.WithTimeout(original, time.Second)
			defer cancel()
			switch change {
			case "raw":
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
				defer cancel()
			case "unbounded":
				ctx = original
			case "foreign":
				foreign := &Gate{}
				var release func()
				var err error
				ctx, release, err = foreign.ExclusiveContext(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			case "cancelled":
				cancel()
			case "copy":
				review = &ControlEpochReview{self: review.self, gate: review.gate, dir: review.dir, lock: review.lock, info: review.info, ref: review.ref}
			case "closed":
				_ = review.Close()
			case "marker":
				if err := os.WriteFile(filepath.Join(root, selfControlLock), []byte("changed marker\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := review.WithRemove(ctx, func() error { t.Fatal("invalid owner reached removal"); return nil }); err == nil {
				t.Fatal("unowned or stale removal admitted")
			}
		})
	}
}
