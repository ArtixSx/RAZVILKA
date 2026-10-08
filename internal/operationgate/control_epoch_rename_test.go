package operationgate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestControlEpochRenameUsesOriginalOwnerAndPreservesActualSyscallError(t *testing.T) {
	_, original, review, root := epochReviewFixture(t)
	ctx, cancel := context.WithTimeout(original, time.Second)
	defer cancel()
	if !review.MatchesControlRoot(root) || review.MatchesControlRoot(root+"-other") {
		t.Fatal("configured root comparison lost the original owner")
	}
	base := t.TempDir()
	stage, target := filepath.Join(base, "stage"), filepath.Join(base, "target")
	if err := os.WriteFile(stage, []byte("actual staged image"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err := review.WithRename(ctx, func() error { calls++; return os.Rename(stage, target) }); err != nil || calls != 1 {
		t.Fatal("actual staged rename", err, calls)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "actual staged image" {
		t.Fatal("rename did not publish exact staged bytes", err)
	}
	var syscallErr error
	if err := review.WithRename(ctx, func() error { syscallErr = os.Rename(stage, target); return syscallErr }); syscallErr == nil || !errors.Is(err, syscallErr) {
		t.Fatal("actual rename error swallowed", err, syscallErr)
	}
	if _, err := RequestSelfUpdateStop(context.Background(), root, controlTestID, 7); err != nil {
		t.Fatal(err)
	}
	if err := review.WithRename(ctx, func() error { t.Fatal("rename after Stop"); return nil }); !errors.Is(err, ErrSelfUpdateStopped) {
		t.Fatal("Stop did not fence late publication", err)
	}
}

func TestControlEpochRenameLinearizesOnlyItsShortLeafWithStop(t *testing.T) {
	_, original, review, root := epochReviewFixture(t)
	ctx, cancel := context.WithTimeout(original, 2*time.Second)
	defer cancel()
	stage, target := filepath.Join(t.TempDir(), "stage"), filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(stage, []byte("ready before admission"), 0600); err != nil {
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
		result <- review.WithRename(ctx, func() error {
			close(entered)
			<-release // Test barrier immediately before the actual rename syscall.
			return os.Rename(stage, target)
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("rename not admitted", ctx.Err())
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	_, err := RequestSelfUpdateStop(stopCtx, root, controlTestID, 7)
	stopCancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Stop overlapped admitted publication", err)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, err := RequestSelfUpdateStop(ctx, root, controlTestID, 7); err != nil {
		t.Fatal("rename kept Stop locked during later sync/readback", err)
	}
}

func TestControlEpochRenameRefusesUnownedUnboundedCopiedClosedAndDrifted(t *testing.T) {
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
				if review.MatchesControlRoot(root) {
					t.Fatal("closed owner matched configured root")
				}
			case "marker":
				if err := os.WriteFile(filepath.Join(root, selfControlLock), []byte("changed marker\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := review.WithRename(ctx, func() error { t.Fatal("invalid owner reached rename"); return nil }); err == nil {
				t.Fatal("unowned or stale publication admitted")
			}
		})
	}
}
