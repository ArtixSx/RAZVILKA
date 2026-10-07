package operationgate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func epochReviewFixture(t *testing.T) (*Gate, context.Context, *ControlEpochReview, string) {
	t.Helper()
	path := controlTestRoot(t)
	if _, err := InitializeSelfUpdateControl(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	g := &Gate{}
	ctx, release, err := g.ExclusiveContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	r, err := g.ReviewControlEpoch(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return g, ctx, r, path
}

func TestControlEpochRequiresOriginalAdmissionAndExistingOwner(t *testing.T) {
	g := &Gate{}
	path := controlTestRoot(t)
	if _, err := g.ReviewControlEpoch(context.Background(), path); !errors.Is(err, ErrBusy) {
		t.Fatal("raw context", err)
	}
	ctx, release, err := g.ExclusiveContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := g.ReviewControlEpoch(ctx, path); !errors.Is(err, ErrSelfUpdateStopJournal) {
		t.Fatal("missing owner", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("review created control", err)
	}
}

func TestControlEpochCurrentStartStopAndDetachedReference(t *testing.T) {
	g, ctx, r, path := epochReviewFixture(t)
	ref := r.Reference()
	ref.Sequence++
	ref.InstallationID = controlOtherID
	if err := r.Current(ctx); err != nil {
		t.Fatal("detached ref changed original", err)
	}
	called := 0
	callbackErr := errors.New("actual start refused")
	if err := r.WithStart(ctx, func() error { called++; _ = g.Snapshot(); return callbackErr }); !errors.Is(err, callbackErr) || called != 1 {
		t.Fatal("start error lost", err, called)
	}
	if _, err := RequestSelfUpdateStop(context.Background(), path, controlTestID, 7); err != nil {
		t.Fatal(err)
	}
	if err := r.Current(ctx); !errors.Is(err, ErrSelfUpdateStopped) {
		t.Fatal("Stop not revoked", err)
	}
	if err := r.WithStart(ctx, func() error { t.Fatal("start after Stop"); return nil }); !errors.Is(err, ErrSelfUpdateStopped) {
		t.Fatal(err)
	}
	if g.Snapshot().Active != 1 {
		t.Fatal("Stop released original before cleanup")
	}
}

func TestControlEpochStartLinearizesDurableStopOnlyForBegin(t *testing.T) {
	_, ctx, r, path := epochReviewFixture(t)
	entered, finish, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() { result <- r.WithStart(ctx, func() error { close(entered); <-finish; return nil }) }()
	<-entered
	stopCtx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := RequestSelfUpdateStop(stopCtx, path, controlTestID, 7); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Stop overlapped actual Begin", err)
	}
	close(finish)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, err := RequestSelfUpdateStop(context.Background(), path, controlTestID, 7); err != nil {
		t.Fatal("lock retained after Start", err)
	}
	if err := r.Current(ctx); !errors.Is(err, ErrSelfUpdateStopped) {
		t.Fatal(err)
	}
}

func TestControlEpochForeignExpiredClosedAndFreshSameGate(t *testing.T) {
	g, ctx, r, _ := epochReviewFixture(t)
	copy := &ControlEpochReview{self: r.self, gate: r.gate, dir: r.dir, lock: r.lock, info: r.info, ref: r.ref}
	if err := copy.Current(ctx); !errors.Is(err, ErrSelfUpdateStopChanged) {
		t.Fatal("copied handle", err)
	}
	if err := copy.Close(); !errors.Is(err, ErrSelfUpdateStopChanged) {
		t.Fatal("copy closed original", err)
	}
	foreign := &Gate{}
	other, releaseOther, err := foreign.ExclusiveContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer releaseOther()
	if err := r.Current(other); !errors.Is(err, ErrBusy) {
		t.Fatal("foreign gate", err)
	}
	if err := r.Current(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal("raw context", err)
	}
	child, cancel := context.WithCancel(ctx)
	cancel()
	if err := r.Current(child); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Current(ctx); !errors.Is(err, ErrSelfUpdateStopChanged) {
		t.Fatal("closed handle", err)
	}
	if g.Snapshot().Active != 1 {
		t.Fatal("control close released Gate")
	}
}

func TestControlEpochPermanentLockReplacementAndMarkerDriftRefuse(t *testing.T) {
	for _, change := range []string{"replace", "marker"} {
		t.Run(change, func(t *testing.T) {
			_, ctx, r, path := epochReviewFixture(t)
			lockPath := filepath.Join(path, selfControlLock)
			if change == "replace" {
				if err := os.Rename(lockPath, lockPath+".old"); err != nil {
					t.Skip("platform prevents replacement of retained open lock", err)
				}
				if err := os.WriteFile(lockPath, []byte(selfControlMarker), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(lockPath, []byte("wrong marker\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := r.Current(ctx); !errors.Is(err, ErrSelfUpdateStopJournal) {
				t.Fatal("changed permanent owner accepted", err)
			}
			if err := r.WithStart(ctx, func() error { t.Fatal("start after owner replacement"); return nil }); !errors.Is(err, ErrSelfUpdateStopJournal) {
				t.Fatal(err)
			}
		})
	}
}

func TestControlEpochOriginalControlRootReplacementRefuses(t *testing.T) {
	_, ctx, r, path := epochReviewFixture(t)
	if err := os.Rename(path, path+".old"); err != nil {
		t.Skip("platform prevents replacement of retained open control root", err)
	}
	if _, err := InitializeSelfUpdateControl(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if err := r.Current(ctx); !errors.Is(err, ErrSelfUpdateStopJournal) {
		t.Fatal("replacement control root accepted", err)
	}
}
