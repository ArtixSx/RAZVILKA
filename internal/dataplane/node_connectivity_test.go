package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

func TestNodeConnectivityUsesOwnedLifecycleWithoutServiceEvidence(t *testing.T) {
	c := fakeExactNodeChecker(t)
	calls, cleanup := 0, 0
	c.connectivityProbe = func(context.Context, string) (int, error) { calls++; return 204, nil }
	c.serviceProbe = func(context.Context, string, string, string, catalog.Service) (evidence.ProbeEvidence, error) {
		t.Fatal("service probe called")
		return evidence.ProbeEvidence{}, nil
	}
	c.cleanup = func(context.Context, exactNodeSession) error { cleanup++; return nil }
	r := checkedNodeRequest()
	result, err := c.CheckConnectivity(context.Background(), NodeConnectivityRequest{NodeID: r.NodeID, Outbound: r.Outbound, NetworkProfile: r.NetworkProfile})
	if err != nil || !result.Ready || !result.CleanupVerified || result.Verdict != evidence.VerdictPass || result.HTTPStatus != 204 || calls != 1 || cleanup != 1 || result.ExpiresAt.Sub(result.CheckedAt) != NodeConnectivityTTL {
		t.Fatalf("result=%+v err=%v calls=%d cleanup=%d", result, err, calls, cleanup)
	}
}

func TestNodeConnectivityRejectsLateFailuresAndMissingControl(t *testing.T) {
	for _, name := range []string{"status", "transport", "control", "network", "cleanup", "resource", "cancel"} {
		t.Run(name, func(t *testing.T) {
			c := fakeExactNodeChecker(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			blocked := false
			ctx = WithNodeResourceGuard(ctx, func(context.Context, string, netip.Addr) error {
				if blocked {
					return ErrNodeResourceDenied
				}
				return nil
			})
			cleanup, probes := 0, 0
			c.cleanup = func(context.Context, exactNodeSession) error {
				cleanup++
				if name == "cleanup" {
					return errors.New("test")
				}
				return nil
			}
			c.connectivityProbe = func(context.Context, string) (int, error) {
				probes++
				switch name {
				case "status":
					return 200, nil
				case "network":
					c.FreshProfile = func(context.Context) (string, error) { return "network-unknown", nil }
				case "resource":
					blocked = true
				case "cancel":
					cancel()
				}
				return 204, nil
			}
			c.serviceProbe = func(context.Context, string, string, string, catalog.Service) (evidence.ProbeEvidence, error) {
				t.Fatal("connectivity invoked diagnostic service probe")
				return evidence.ProbeEvidence{}, nil
			}
			if name == "transport" {
				c.dialTransport = func(context.Context, exactNodeEndpoint, []netip.Addr) (bool, error) { return true, errors.New("test") }
			}
			if name == "control" {
				c.directEgress = func(context.Context) (string, error) { return "", errors.New("test") }
			}
			r := checkedNodeRequest()
			result, _ := c.CheckConnectivity(ctx, NodeConnectivityRequest{NodeID: r.NodeID, Outbound: r.Outbound, NetworkProfile: r.NetworkProfile})
			if result.Ready || result.Verdict == evidence.VerdictPass {
				t.Fatalf("promoted failed check: %+v", result)
			}
			if name == "cleanup" && result.CleanupVerified {
				t.Fatal("cleanup gap accepted")
			}
			if name == "transport" {
				if probes != 0 || cleanup != 0 || !result.CleanupVerified || result.DirectControl != "not_run" || result.Stage != "transport" || result.ErrorCode != "node-transport-failed" {
					t.Fatal(result)
				}
			} else if cleanup != 1 {
				t.Fatal("cleanup not joined", cleanup)
			}
		})
	}
}

func TestNodeConnectivityFixedTargetDenialPrecedesDNS(t *testing.T) {
	c := fakeExactNodeChecker(t)
	c.resolve = func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("DNS ran after target denial")
		return nil, nil
	}
	ctx := WithNodeResourceGuard(context.Background(), func(_ context.Context, host string, _ netip.Addr) error {
		if host == "www.gstatic.com" {
			return ErrNodeResourceDenied
		}
		return nil
	})
	if _, err := c.probeConnectivity(ctx, "127.0.0.1:19291"); !errors.Is(err, ErrNodeResourceDenied) {
		t.Fatal(err)
	}
}
