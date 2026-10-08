package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/ArtixSx/razvilka/internal/evidence"
)

func TestNodeResourceGuardExcludedEgressNeverFallsBack(t *testing.T) {
	for _, pair := range []bool{false, true} {
		calls := 0
		ctx := WithNodeResourceGuard(context.Background(), func(_ context.Context, host string, _ netip.Addr) error {
			if host == "www.cloudflare.com" {
				return ErrNodeResourceDenied
			}
			return nil
		})
		get := func(context.Context, nodeEgressEndpoint, string) (string, error) { calls++; return "198.51.100.7", nil }
		var err error
		if pair {
			result := probeNodeEgressPair(ctx, "127.0.0.1:19181", get)
			err = result.directErr
		} else {
			_, err = probeNodeEgress(ctx, "", get)
		}
		if !errors.Is(err, ErrNodeResourceDenied) || calls != 0 {
			t.Fatal("excluded CF recipe fell back", err, calls)
		}
	}
}

func TestNodeResourceGuardEgressDenialCannotBecomeGenericFailure(t *testing.T) {
	calls := 0
	get := func(context.Context, nodeEgressEndpoint, string) (string, error) {
		calls++
		return "", ErrNodeResourceDenied
	}
	result := probeNodeEgressPair(context.Background(), "127.0.0.1:19181", get)
	if !errors.Is(result.directErr, ErrNodeResourceDenied) || !errors.Is(result.proxyErr, ErrNodeResourceDenied) || calls != 1 {
		t.Fatal(result, calls)
	}
}

func TestNodeResourceGuardResolvedPinRefusesBeforeDial(t *testing.T) {
	blocked := netip.MustParseAddr("1.1.1.2")
	ctx := WithNodeResourceGuard(context.Background(), func(_ context.Context, _ string, address netip.Addr) error {
		if address == blocked {
			return ErrNodeResourceDenied
		}
		return nil
	})
	p := nodeEgressHTTP{resolve: func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), blocked}, nil
	}}
	if _, err := p.pin(ctx, nodeEgressEndpoint{url: "https://www.cloudflare.com/cdn-cgi/trace"}); !errors.Is(err, ErrNodeResourceDenied) {
		t.Fatal("excluded member of DNS set admitted", err)
	}
	if err := checkNodeResource(ctx, "allowed.example", netip.Addr{}); !errors.Is(err, ErrNodeResourceDenied) {
		t.Fatal("later target bypassed sticky denial", err)
	}
}

func TestNodeResourceGuardCheckBookendRevokesSuccessAndCleans(t *testing.T) {
	c := fakeExactNodeChecker(t)
	refused, cleaned := false, 0
	ctx := WithNodeResourceGuard(context.Background(), func(context.Context, string, netip.Addr) error {
		if refused {
			return ErrNodeResourceDenied
		}
		return nil
	})
	c.cleanup = func(context.Context, exactNodeSession) error { cleaned++; refused = true; return nil }
	r, err := c.Check(ctx, checkedNodeRequest())
	if !errors.Is(err, ErrNodeResourceDenied) || r.Available || r.Verdict != evidence.VerdictInconclusive || r.EgressIP != "" || r.Evidence.AssuranceLevel().AtLeast(evidence.Service) || cleaned != 1 {
		t.Fatalf("result=%+v err=%v cleaned=%d", r, err, cleaned)
	}
}

func TestNodeResourceGuardAuxiliaryDenialStartsNoNodeTransport(t *testing.T) {
	c := fakeExactNodeChecker(t)
	dns := 0
	c.resolve = func(context.Context, string) ([]netip.Addr, error) {
		dns++
		return []netip.Addr{netip.MustParseAddr("203.0.113.8")}, nil
	}
	ctx := WithNodeResourceGuard(context.Background(), func(_ context.Context, host string, _ netip.Addr) error {
		if host == "www.cloudflare.com" {
			return ErrNodeResourceDenied
		}
		return nil
	})
	r, err := c.Check(ctx, checkedNodeRequest())
	if !errors.Is(err, ErrNodeResourceDenied) || r.Available || r.Verdict != evidence.VerdictInconclusive || dns != 0 {
		t.Fatal(r, err, dns)
	}
}
