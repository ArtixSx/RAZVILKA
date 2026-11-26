package startuptools

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Lock-lifecycle model only: these objects cannot pass native source capture,
// execute a tool or issue a backend inventory image.
func readObservationLockModel(t *testing.T) (*Lease, *toolReadObservation, context.Context, context.CancelFunc) {
	t.Helper()
	lifetime, closeLifetime := context.WithCancel(context.Background())
	t.Cleanup(closeLifetime)
	base, cancel := context.WithTimeout(lifetime, time.Second)
	l := &Lease{gate: make(chan struct{}, 1), lifetime: lifetime, review: &heldReview{}, digest: strings.Repeat("a", 64), identity: netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "12345678-1234-1234-1234-123456789abc", Inode: 123}}
	l.gate <- struct{}{}
	deadline, _ := base.Deadline()
	o := &toolReadObservation{lease: l, review: l.review, digest: l.digest, identity: l.identity, deadline: deadline, active: true}
	o.self = o
	scoped := context.WithValue(base, toolReadObservationKey{}, o)
	o.ctx = scoped
	return l, o, scoped, cancel
}

func TestReadObservationCopiedForeignExpiredMarkersNeverFallback(t *testing.T) {
	for _, mode := range []string{"copy", "foreign-lease", "expired", "cancelled", "unbounded-context", "extended-context", "foreign-marker"} {
		t.Run(mode, func(t *testing.T) {
			l, o, ctx, cancel := readObservationLockModel(t)
			defer cancel()
			switch mode {
			case "copy":
				copy := &toolReadObservation{self: o, lease: l, review: o.review, digest: o.digest, identity: o.identity, deadline: o.deadline, ctx: o.ctx, active: true}
				ctx = context.WithValue(ctx, toolReadObservationKey{}, copy)
			case "foreign-lease":
				l = &Lease{gate: make(chan struct{}, 1), lifetime: o.ctx, review: o.review, digest: o.digest, identity: o.identity}
				l.gate <- struct{}{}
			case "expired":
				o.active = false
			case "cancelled":
				cancel()
			case "unbounded-context":
				ctx = context.WithoutCancel(ctx)
			case "extended-context":
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(context.WithoutCancel(ctx), time.Hour)
				defer stop()
			case "foreign-marker":
				ctx = context.WithValue(ctx, toolReadObservationKey{}, "copied string")
			}
			if err := l.lock(ctx); !errors.Is(err, ErrUnknown) {
				if err == nil {
					l.unlock()
				}
				t.Fatal("invalid marker reached original gate", err)
			}
			if err := readObservationEffectRefusal(ctx); !errors.Is(err, ErrUnknown) {
				t.Fatal("effect role silently fell back", err)
			}
		})
	}
}

func TestReadObservationRevocationCancelsQueuedReadAndJoinsHeldRead(t *testing.T) {
	l, o, ctx, cancel := readObservationLockModel(t)
	defer cancel()
	if err := l.lock(ctx); err != nil {
		t.Fatal(err)
	}
	queued := make(chan error, 1)
	deadline, _ := ctx.Deadline()
	queuedCtx, stopQueued := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	defer stopQueued()
	go func() {
		err := l.lock(queuedCtx)
		if err == nil {
			l.unlock()
		}
		queued <- err
	}()
	closed := make(chan struct{})
	go func() {
		o.mu.Lock()
		o.active = false
		o.mu.Unlock()
		cancel()
		o.users.Wait()
		close(closed)
	}()
	select {
	case err := <-queued:
		if !errors.Is(err, ErrUnknown) {
			t.Fatal("queued read survived", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued read waited for unrelated held gate after revoke")
	}
	select {
	case <-closed:
		t.Fatal("scope closed before original held read released")
	default:
	}
	l.unlock()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("original read failed to join")
	}
	if err := l.lock(ctx); !errors.Is(err, ErrUnknown) {
		t.Fatal("late marker reused", err)
	}
}
