package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// These tests exercise the marker's comparison/lifetime only. The deliberately
// empty child does not provide native health or permission to promote policy.
func mihomoHealthMarkerFixture(t *testing.T) (*mihomoLiveResource, context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return mihomoHealthMarkerForContext(ctx), ctx, cancel
}

func mihomoHealthMarkerForContext(ctx context.Context) *mihomoLiveResource {
	r := &mihomoLiveResource{scope: &executionResourceScope{ctx: ctx}, child: &components.MihomoLiveProcess{}, sidecar: &mihomoLiveSidecar{}, control: &operationgate.ControlEpochReview{}}
	r.self = r
	deadline, _ := ctx.Deadline()
	h := &mihomoLiveHealthHandoff{owner: r, scope: r.scope, child: r.child, sidecar: r.sidecar, control: r.control, scopeContext: ctx, context: ctx, deadline: deadline}
	h.self = h
	r.healthHandoff = h
	return r
}

func TestMihomoHealthHandoffIsOriginalAndOneUse(t *testing.T) {
	r, ctx, _ := mihomoHealthMarkerFixture(t)
	ctx = r.scope.contextWith(ctx)
	if _, err := r.takeHealthHandoff(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.takeHealthHandoff(ctx); err == nil {
		t.Fatal("replayed marker")
	}
}

func TestMihomoHealthHandoffRefusesChangedOwnerAndLifetime(t *testing.T) {
	for _, name := range []string{"copied-marker", "foreign-owner", "scope", "scope-lifetime", "control", "foreign-context", "child", "sidecar", "closed", "active", "retired", "deadline-expired", "canceled-original", "canceled-current", "copied-resource"} {
		t.Run(name, func(t *testing.T) {
			r, ctx, cancel := mihomoHealthMarkerFixture(t)
			ctx = r.scope.contextWith(ctx)
			switch name {
			case "copied-marker":
				copy := *r.healthHandoff
				r.healthHandoff = &copy
			case "foreign-owner":
				r.healthHandoff.owner = &mihomoLiveResource{}
			case "scope":
				r.scope = &executionResourceScope{}
			case "scope-lifetime":
				r.scope.ctx = context.Background()
			case "control":
				r.control = &operationgate.ControlEpochReview{}
			case "foreign-context":
				ctx = context.WithValue(ctx, syntheticExecutionRegistrarKey{}, &executionResourceScope{})
			case "child":
				r.child = &components.MihomoLiveProcess{}
			case "sidecar":
				r.sidecar = &mihomoLiveSidecar{}
			case "closed":
				r.closed = true
			case "active":
				r.active = true
			case "retired":
				r.retired = true
			case "deadline-expired":
				var shorter context.CancelFunc
				ctx, shorter = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer shorter()
			case "canceled-original":
				cancel()
			case "canceled-current":
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
			case "copied-resource":
				// Do not copy a mutex: construct the same visible fields.
				r = &mihomoLiveResource{self: r, scope: r.scope, child: r.child, sidecar: r.sidecar, healthHandoff: r.healthHandoff}
			}
			if _, err := r.takeHealthHandoff(ctx); err == nil {
				t.Fatal("accepted changed original/lifetime")
			}
			if r.healthHandoff != nil {
				t.Fatal("refused marker remained usable")
			}
		})
	}
}

func TestMihomoHealthHandoffRetainsCancellationCause(t *testing.T) {
	r, ctx, cancel := mihomoHealthMarkerFixture(t)
	ctx = r.scope.contextWith(ctx)
	cancel()
	if _, err := r.takeHealthHandoff(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestMihomoHealthHandoffExistingShieldDoesNotRenewOriginalLifetime(t *testing.T) {
	r, original, _ := mihomoHealthMarkerFixture(t)
	shield, release := shieldLiveMutation(r.scope.contextWith(original))
	defer release()
	h, err := r.takeHealthHandoff(shield)
	if err != nil {
		t.Fatal("legitimate original mutation shield refused", err)
	}
	held, finish := h.comparisonContext(shield)
	defer finish()
	deadline, _ := held.Deadline()
	if !deadline.Equal(h.deadline) {
		t.Fatal("shield renewed original Health comparison lifetime")
	}
	for _, cause := range []string{"canceled", "expired"} {
		t.Run(cause, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			if cause == "expired" {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			}
			defer cancel()
			r := mihomoHealthMarkerForContext(ctx)
			shield, release := shieldLiveMutation(r.scope.contextWith(ctx))
			defer release()
			if cause == "canceled" {
				cancel()
			}
			if shield.Err() != nil {
				t.Fatal("fixture shield was not live")
			}
			_, err := r.takeHealthHandoff(shield)
			wanted := context.Canceled
			if cause == "expired" {
				wanted = context.DeadlineExceeded
			}
			if !errors.Is(err, wanted) || r.healthHandoff != nil {
				t.Fatal("shield reused dead original Health", err)
			}
		})
	}
}

func TestMihomoHealthHandoffComparisonUsesEarlierIncomingDeadline(t *testing.T) {
	r, original, _ := mihomoHealthMarkerFixture(t)
	incoming, cancel := context.WithTimeout(r.scope.contextWith(original), time.Second)
	defer cancel()
	h, err := r.takeHealthHandoff(incoming)
	if err != nil {
		t.Fatal(err)
	}
	held, finish := h.comparisonContext(incoming)
	defer finish()
	actual, _ := held.Deadline()
	wanted, _ := incoming.Deadline()
	if !actual.Equal(wanted) {
		t.Fatal("comparison extended earlier incoming deadline")
	}
	cancel()
	if !errors.Is(held.Err(), context.Canceled) {
		t.Fatal("incoming cancellation was detached", held.Err())
	}
}

func TestMihomoHealthHandoffComparisonJoinsOriginalCancellation(t *testing.T) {
	r, original, cancelOriginal := mihomoHealthMarkerFixture(t)
	shield, release := shieldLiveMutation(r.scope.contextWith(original))
	defer release()
	h, err := r.takeHealthHandoff(shield)
	if err != nil {
		t.Fatal(err)
	}
	held, finish := h.comparisonContext(shield)
	defer finish()
	cancelOriginal()
	select {
	case <-held.Done():
	case <-time.After(time.Second):
		t.Fatal("original cancellation did not join bounded comparison")
	}
	if !errors.Is(held.Err(), context.Canceled) || shield.Err() != nil {
		t.Fatal("lost original cancellation or changed mutation shield", held.Err(), shield.Err())
	}
}

func TestMihomoHealthHandoffDNSRequiresExactEntireAnswerSet(t *testing.T) {
	url := "https://service.example.com/"
	addresses := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.1.1.2")}
	before := map[string][]netip.Addr{url: addresses}
	if !mihomoHealthDNSMatches(before, url, addresses) {
		t.Fatal("same complete set refused")
	}
	for _, answer := range [][]netip.Addr{nil, addresses[:1], {addresses[0], netip.MustParseAddr("1.1.1.3")}, {addresses[0], addresses[1], netip.MustParseAddr("1.1.1.3")}} {
		if mihomoHealthDNSMatches(before, url, answer) {
			t.Fatal("changed set accepted")
		}
	}
	if mihomoHealthDNSMatches(before, "https://other.example.com/", addresses) {
		t.Fatal("foreign raw URL accepted")
	}
}
