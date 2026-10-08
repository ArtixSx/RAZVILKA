package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

func TestResearchSelectedEndpointPassesSingletonAndKeepsHostname(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	c := &ExactNodeChecker{dialTransport: func(_ context.Context, e exactNodeEndpoint, ips []netip.Addr) (bool, error) {
		if len(ips) != 1 || e.Host != "vpn.example.com" {
			t.Fatal("lost identity")
		}
		if ips[0] == a {
			return true, errors.New("no")
		}
		return true, nil
	}}
	got, e := c.selectEndpoint(context.Background(), exactNodeEndpoint{Protocol: "vless", Host: "vpn.example.com", Port: 443}, []netip.Addr{a, b})
	if e != nil || got.Address != b {
		t.Fatal(got, e)
	}
}
func TestResearchRestrictedDiagnosticNeverCreatesApplyProof(t *testing.T) {
	now := time.Now()
	called := 0
	c := &ExactNodeChecker{serviceProbe: func(_ context.Context, address, route, ip string, s catalog.Service) (evidence.ProbeEvidence, error) {
		called++
		return evidence.ProbeEvidence{SchemaVersion: evidence.ProbeSchemaVersion, Outcome: evidence.OutcomeServiceAccepted, HTTPStatus: 200, Service: "telegram", ProbeID: "proof", StartedAt: now.Add(-time.Second), FinishedAt: now, Verdict: evidence.VerdictPass, RoutePathID: route, ExpectedRoutePathID: route, ObservedRoutePathID: route}, nil
	}}
	r := NodeCheckResult{RoutePathID: "sing-box:node-a"}
	c.probeRestrictedDiagnostic(context.Background(), &r, "127.0.0.1:19181", "1.1.1.1", catalog.Service{ID: "telegram", ProbeURL: "https://telegram.org/"})
	if called != 1 || r.Available || r.Verdict != evidence.VerdictInconclusive || r.EgressIP != "" || len(r.Stages) != 1 || r.Stages[0].Status != "response_observed" || r.Evidence.Valid() {
		t.Fatalf("promoted: %+v", r)
	}
}
func TestResearchRestrictedDiagnosticObeysCancellationAndBudget(t *testing.T) {
	called := 0
	c := &ExactNodeChecker{serviceProbe: func(context.Context, string, string, string, catalog.Service) (evidence.ProbeEvidence, error) {
		called++
		return evidence.ProbeEvidence{}, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := NodeCheckResult{}
	service := catalog.Service{ID: "telegram", ProbeURL: "https://telegram.org/"}
	c.probeRestrictedDiagnostic(ctx, &r, "127.0.0.1:19181", "1.1.1.1", service)
	ctx, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	c.probeRestrictedDiagnostic(ctx, &r, "127.0.0.1:19181", "1.1.1.1", service)
	if called != 0 {
		t.Fatal("ran outside budget")
	}
}

func TestResearchRestrictedDiagnosticRefusesMalformedOrExcludedTarget(t *testing.T) {
	for _, excluded := range []bool{false, true} {
		called := 0
		c := &ExactNodeChecker{serviceProbe: func(context.Context, string, string, string, catalog.Service) (evidence.ProbeEvidence, error) {
			called++
			return evidence.ProbeEvidence{}, nil
		}}
		ctx := context.Background()
		service := catalog.Service{ID: "telegram"}
		if excluded {
			service.ProbeURL = "https://telegram.org/"
			ctx = WithNodeResourceGuard(ctx, func(context.Context, string, netip.Addr) error { return ErrNodeResourceDenied })
		}
		r := NodeCheckResult{RoutePathID: "sing-box:node-a"}
		c.probeRestrictedDiagnostic(ctx, &r, "127.0.0.1:19181", "1.1.1.1", service)
		if called != 0 || len(r.Stages) != 0 || r.Available || r.Evidence.Valid() {
			t.Fatal("invalid or excluded target reached the diagnostic", excluded, called, r)
		}
	}
}
func TestResearchRestrictedDiagnosticRejectsWrongObservedRoute(t *testing.T) {
	now := time.Now()
	called := 0
	c := &ExactNodeChecker{serviceProbe: func(context.Context, string, string, string, catalog.Service) (evidence.ProbeEvidence, error) {
		called++
		return evidence.ProbeEvidence{SchemaVersion: evidence.ProbeSchemaVersion, Outcome: evidence.OutcomeServiceAccepted, HTTPStatus: 200, Service: "telegram", ProbeID: "proof", StartedAt: now.Add(-time.Second), FinishedAt: now, Verdict: evidence.VerdictPass, RoutePathID: "direct", ExpectedRoutePathID: "direct", ObservedRoutePathID: "direct"}, nil
	}}
	r := NodeCheckResult{RoutePathID: "sing-box:node-a"}
	c.probeRestrictedDiagnostic(context.Background(), &r, "127.0.0.1:19181", "1.1.1.1", catalog.Service{ID: "telegram", ProbeURL: "https://telegram.org/"})
	if called != 1 || len(r.Stages) != 1 || r.Stages[0].Status != "unknown" || r.Available || r.Evidence.Valid() {
		t.Fatal("wrong identity promoted")
	}
}
