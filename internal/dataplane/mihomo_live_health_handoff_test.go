package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
)

// These tests exercise the marker's comparison/lifetime only. The deliberately
// empty child does not provide native health or permission to promote policy.
func mihomoHealthMarkerFixture(t *testing.T) (*mihomoLiveResource, context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	r := &mihomoLiveResource{scope: &executionResourceScope{}, child: &components.MihomoLiveProcess{}, sidecar: &mihomoLiveSidecar{}}
	r.self = r
	ctx = context.WithValue(ctx, syntheticExecutionRegistrarKey{}, r.scope)
	deadline, _ := ctx.Deadline()
	h := &mihomoLiveHealthHandoff{owner: r, scope: r.scope, child: r.child, sidecar: r.sidecar, context: ctx, deadline: deadline}
	h.self = h
	r.healthHandoff = h
	return r, ctx, cancel
}

func TestMihomoHealthHandoffIsOriginalAndOneUse(t *testing.T) {
	r, ctx, _ := mihomoHealthMarkerFixture(t)
	if _, err := r.takeHealthHandoff(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.takeHealthHandoff(ctx); err == nil {
		t.Fatal("replayed marker")
	}
}

func TestMihomoHealthHandoffRefusesChangedOwnerAndLifetime(t *testing.T) {
	for _, name := range []string{"copied-marker", "foreign-owner", "scope", "foreign-context", "child", "sidecar", "closed", "active", "retired", "deadline", "canceled-original", "canceled-current", "copied-resource"} {
		t.Run(name, func(t *testing.T) {
			r, ctx, cancel := mihomoHealthMarkerFixture(t)
			switch name {
			case "copied-marker":
				copy := *r.healthHandoff
				r.healthHandoff = &copy
			case "foreign-owner":
				r.healthHandoff.owner = &mihomoLiveResource{}
			case "scope":
				r.scope = &executionResourceScope{}
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
			case "deadline":
				var shorter context.CancelFunc
				ctx, shorter = context.WithTimeout(ctx, time.Second)
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
	cancel()
	if _, err := r.takeHealthHandoff(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
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
