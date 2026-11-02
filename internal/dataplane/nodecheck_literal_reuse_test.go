package dataplane

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// Modeled runtime/admission plus real local verified TLS through real SOCKS.
// No actual proxy engine or router is started by this fixture.
func guardedLiteralFixture(t *testing.T, delay time.Duration) (*ExactNodeChecker, NodeCheckRequest, *atomic.Int32) {
	t.Helper()
	calls := new(atomic.Int32)
	server, roots, names := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-time.After(delay):
			w.WriteHeader(204)
		case <-r.Context().Done():
		}
	})
	socks := newPinnedSOCKSFixture(t, server.Listener.Addr().String(), false)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			select {
			case <-names:
			case <-socks.requests:
			case <-stop:
				return
			}
		}
	}()
	checker := fakeExactNodeChecker(t)
	checker.now = time.Now
	checker.serviceTLSRoots = roots
	checker.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	checker.prepare = func(context.Context, exactNodeSession, NodeCheckRequest, exactNodeEndpoint) (exactNodeSession, error) {
		return exactNodeSession{Address: socks.address, Spec: ProcessSpec{Binary: "sing-box"}}, nil
	}
	checker.serviceProbe = checker.probeService
	checker.serviceIPProbe = checker.probeServiceIP
	request := checkedNodeRequest()
	request.Service.ProbeURL = "https://example.com/"
	return checker, request, calls
}
func TestGuardedLiteralFirstIPSingleRequest(t *testing.T) {
	checker, request, calls := guardedLiteralFixture(t, 0)
	ctx := WithNodeResourceGuard(context.Background(), func(context.Context, string, netip.Addr) error { return nil })
	result, err := checker.Check(ctx, request)
	if err != nil || !result.Available {
		t.Fatalf("real local HTTPS service fixture failed: stage=%s code=%s err=%v", result.Stage, result.ErrorCode, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one exact literal request; got %d", calls.Load())
	}
}
func TestGuardedLiteralLocalPerformance(t *testing.T) {
	if os.Getenv("RAZVILKA_EGRESS_PERF") != "1" {
		t.Skip("opt-in local transport measurement")
	}
	checker, request, calls := guardedLiteralFixture(t, 40*time.Millisecond)
	for i := 0; i < 13; i++ {
		ctx := WithNodeResourceGuard(context.Background(), func(context.Context, string, netip.Addr) error { return nil })
		before := calls.Load()
		start := time.Now()
		result, err := checker.Check(ctx, request)
		elapsed := time.Since(start)
		if err != nil || !result.Available {
			t.Fatal("fixture failed", result.ErrorCode, err)
		}
		t.Log(fmt.Sprintf("literal_sample,%d,%.3f,%d", i, float64(elapsed)/float64(time.Millisecond), calls.Load()-before))
	}
}

func TestGuardedLiteralReuseRevalidatesDNSAndScope(t *testing.T) {
	for _, mode := range []string{"same", "reordered", "removed", "denied-second", "cancel-second-dns", "new-check", "unguarded"} {
		t.Run(mode, func(t *testing.T) {
			checker, request, calls := guardedLiteralFixture(t, 0)
			first := netip.MustParseAddr("1.1.1.1")
			second := netip.MustParseAddr("9.9.9.9")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode != "unguarded" {
				ctx = WithNodeResourceGuard(ctx, func(_ context.Context, _ string, ip netip.Addr) error {
					if mode == "denied-second" && ip == second {
						return ErrNodeResourceDenied
					}
					return nil
				})
			}
			dns := 0
			checker.resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
				if host == "node.example" {
					return []netip.Addr{first}, nil
				}
				dns++
				if dns == 2 {
					switch mode {
					case "removed":
						return []netip.Addr{second}, nil
					case "denied-second", "reordered":
						return []netip.Addr{second, first}, nil
					case "cancel-second-dns":
						cancel()
					}
				}
				return []netip.Addr{first}, nil
			}
			if mode == "unguarded" { // Existing fake domain proof must never supply literal proof.
				base := fakeExactNodeChecker(t)
				checker.serviceProbe = base.serviceProbe
			}
			result, err := checker.Check(ctx, request)
			switch mode {
			case "denied-second", "cancel-second-dns":
				if result.Available || calls.Load() != 1 {
					t.Fatalf("refusal/cancel gained authority: available=%t calls=%d err=%v", result.Available, calls.Load(), err)
				}
			default:
				expected := int32(1)
				if mode == "removed" || mode == "reordered" {
					expected = 2
				}
				if err != nil || !result.Available || calls.Load() != expected {
					t.Fatalf("DNS revalidation failed: available=%t calls=%d expected=%d err=%v", result.Available, calls.Load(), expected, err)
				}
			}
			if mode == "new-check" {
				result, err = checker.Check(ctx, request)
				if err != nil || !result.Available || calls.Load() != 2 {
					t.Fatal("literal proof escaped its Check lifetime")
				}
			}
		})
	}
}
