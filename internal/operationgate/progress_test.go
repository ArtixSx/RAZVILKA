package operationgate

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProgressRetainsOriginalHolderThroughCancellationAndFence(t *testing.T) {
	var g Gate
	ctx, update := WithProgress(WithLabel(context.Background(), "Автопилот"), "autonomy")
	deadline := time.Now().Add(time.Minute)
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	owned, release, err := g.ExclusiveContext(bounded)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	before := g.Snapshot()
	if before.Progress == nil || before.Progress.ID == 0 || before.Progress.Kind != "autonomy" || before.Progress.Phase != "preparing" || before.Progress.DeadlineAt == nil || !before.Progress.DeadlineAt.Equal(deadline) {
		t.Fatalf("missing original holder metadata: %+v", before.Progress)
	}
	generation, _ := g.IdleGeneration()
	update("checking", "youtube")
	cancel()
	update("cleanup", "youtube")
	for _, fenced := range []bool{false, true} {
		if fenced {
			g.FenceJournal()
		}
		s := g.Snapshot()
		if s.Active != 1 || !s.Exclusive || s.Progress == nil || s.Progress.ID != before.Progress.ID || s.Progress.Phase != "cleanup" || s.Progress.ServiceID != "youtube" {
			t.Fatalf("cancellation/fence lost the unfinished owner: %+v", s)
		}
		if got, _ := g.IdleGeneration(); got != generation {
			t.Fatal("progress changed the admission generation")
		}
		if err := g.WithExclusiveContext(owned, func() error { t.Fatal("canceled capability revived"); return nil }); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation contract changed: %v", err)
		}
		if _, err := g.Enter(context.Background()); err == nil {
			t.Fatal("progress or cancellation released the holder")
		}
	}
	release()
	update("reserves", "discord")
	s := g.Snapshot()
	if s.Progress != nil || s.Active != 0 || s.Exclusive || s.State != "recovery-required" {
		t.Fatalf("release retained progress or cleared the fence: %+v", s)
	}
}

func TestProgressAdmissionIsolationAndFailedAdmission(t *testing.T) {
	var g, other Gate
	block, err := g.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, update := WithProgress(context.Background(), "autonomy")
	if _, err := g.Exclusive(ctx); !errors.Is(err, ErrBusy) {
		t.Fatal("busy admission changed", err)
	}
	block()
	first, err := g.Exclusive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	update("checking", "youtube")
	firstID := g.Snapshot().Progress.ID
	foreign, err := other.Exclusive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign()
	if other.Snapshot().Progress != nil {
		t.Fatal("reused context attached an updater to a foreign holder")
	}
	first()
	second, err := g.Exclusive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	update("reserves", "discord")
	if s := g.Snapshot(); s.Progress != nil || s.Active != 1 || !s.Exclusive {
		t.Fatalf("old updater attached to a new admission: %+v", s)
	}
	second()
	nextCtx, nextUpdate := WithProgress(ctx, "autonomy")
	next, err := g.Exclusive(nextCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer next()
	update("cleanup", "old-service")
	nextUpdate("checking", "roblox")
	if p := g.Snapshot().Progress; p == nil || p.ID == firstID || p.Phase != "checking" || p.ServiceID != "roblox" {
		t.Fatalf("new operation was changed by the old updater: %+v", p)
	}
}

func TestProgressSharesOnePresentationHolderWithTheLabel(t *testing.T) {
	var g Gate
	firstCtx, firstUpdate := WithProgress(WithLabel(context.Background(), "first"), "autonomy")
	first, err := g.Enter(firstCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer first()
	secondCtx, secondUpdate := WithProgress(WithLabel(context.Background(), "second"), "autonomy")
	second, err := g.Enter(secondCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer second()
	firstUpdate("checking", "youtube")
	secondUpdate("reserves", "discord")
	if s := g.Snapshot(); s.Operation != "first" || s.Progress == nil || s.Progress.ServiceID != "youtube" || s.Progress.Phase != "checking" {
		t.Fatalf("mixed holder observations: %+v", s)
	}
	first()
	if s := g.Snapshot(); s.Operation != "second" || s.Progress == nil || s.Progress.ServiceID != "discord" || s.Progress.Phase != "reserves" {
		t.Fatalf("released holder still determines progress: %+v", s)
	}
}

func TestProgressClockBoundsAndDetachedSnapshots(t *testing.T) {
	var g Gate
	ctx, update := WithProgress(context.Background(), "autonomy")
	deadline := time.Now().Add(time.Minute)
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	release, err := g.Exclusive(bounded)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	p := g.Snapshot().Progress
	start := p.StartedAt
	if !p.PhaseStartedAt.Equal(start) {
		t.Fatal("pre-admission preparation counted as holder time")
	}
	before := g.snapshotAt(start.Add(-time.Second)).Progress
	if before.ElapsedSeconds != 0 || before.PhaseSeconds != 0 || before.DeadlineExceeded || *before.RemainingSeconds <= 0 {
		t.Fatalf("negative duration escaped: %+v", before)
	}
	for _, delta := range []time.Duration{0, time.Second} {
		expired := g.snapshotAt(deadline.Add(delta)).Progress
		if !expired.DeadlineExceeded || expired.RemainingSeconds == nil || *expired.RemainingSeconds != 0 || expired.ElapsedSeconds < 0 || expired.PhaseSeconds < 0 {
			t.Fatalf("deadline claim changed ownership or budget: %+v", expired)
		}
	}
	near := g.snapshotAt(deadline.Add(-250 * time.Millisecond)).Progress
	if near.DeadlineExceeded || *near.RemainingSeconds != 1 {
		t.Fatalf("positive time left was marked expired: %+v", near)
	}
	p.Phase = "forged"
	*p.DeadlineAt = time.Time{}
	*p.RemainingSeconds = -1
	update("checking", "youtube")
	checking := g.Snapshot().Progress
	update("checking", "youtube")
	repeated := g.Snapshot().Progress
	if checking.Phase != "checking" || !checking.DeadlineAt.Equal(deadline) || *checking.RemainingSeconds < 0 || !checking.PhaseStartedAt.Equal(repeated.PhaseStartedAt) {
		t.Fatal("snapshot mutation leaked or repeated phase renewed its timestamp")
	}
	if p.Phase != "forged" {
		t.Fatal("an already-returned snapshot changed after publication")
	}
}

func TestProgressRejectsRawMetadataAndUnknownKinds(t *testing.T) {
	for _, invalid := range []string{"vless://private-key@host", "../secret", "hello world", strings.Repeat("x", 129), "сервис"} {
		t.Run(invalid[:min(len(invalid), 12)], func(t *testing.T) {
			var g Gate
			ctx, update := WithProgress(context.Background(), "autonomy")
			release, err := g.Exclusive(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			update("checking", "custom.ga-Telegram_1")
			if p := g.Snapshot().Progress; p.ServiceID != "custom.ga-Telegram_1" || p.DeadlineAt != nil || p.RemainingSeconds != nil || p.DeadlineExceeded {
				t.Fatalf("bounded metadata or absent deadline lost: %+v", p)
			}
			update("private error: "+invalid, "youtube")
			if p := g.Snapshot().Progress; p.Phase != "checking" || p.ServiceID != "custom.ga-Telegram_1" {
				t.Fatal("unknown phase modified the publication")
			}
			update("cleanup", invalid)
			b, err := json.Marshal(g.Snapshot())
			if err != nil || strings.Contains(string(b), invalid) || g.Snapshot().Progress.ServiceID != "" {
				t.Fatal("raw metadata was published", string(b), err)
			}
		})
	}
	var g Gate
	ctx, _ := WithProgress(context.Background(), "autonomy")
	ctx, update := WithProgress(ctx, "unknown-private-kind")
	release, err := g.Exclusive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	update("checking", "youtube")
	if g.Snapshot().Progress != nil {
		t.Fatal("unknown kind exposed inherited progress")
	}
}

func TestProgressConcurrentUpdatesAndReadsRemainDetached(t *testing.T) {
	var g Gate
	ctx, update := WithProgress(context.Background(), "autonomy")
	release, err := g.Exclusive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	var wg sync.WaitGroup
	for worker := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 500 {
				if worker == 0 {
					update("checking", "youtube")
				} else if worker == 1 {
					update("reserves", "discord")
				} else {
					s := g.Snapshot()
					p := s.Progress
					if s.State != "busy" || s.Active != 1 || p == nil || p.ID == 0 || !(p.Phase == "preparing" && p.ServiceID == "" || p.Phase == "checking" && p.ServiceID == "youtube" || p.Phase == "reserves" && p.ServiceID == "discord") {
						t.Errorf("mixed progress publication: %+v", p)
						return
					}
					p.ServiceID = "detached-client-copy"
				}
			}
		}()
	}
	wg.Wait()
	if _, err := g.Enter(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal("concurrent progress released ownership")
	}
}
