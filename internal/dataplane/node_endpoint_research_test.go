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
	c.probeRestrictedDiagnostic(context.Background(), &r, "127.0.0.1:19181", "203.0.113.2", catalog.Service{ID: "telegram"})
	if called != 1 || r.Available || r.Verdict != evidence.VerdictInconclusive || r.EgressIP != "" || r.Stages[0].Status != "response_observed" || r.Evidence.Valid() {
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
	c.probeRestrictedDiagnostic(ctx, &r, "", "", catalog.Service{})
	ctx, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	c.probeRestrictedDiagnostic(ctx, &r, "", "", catalog.Service{})
	if called != 0 {
		t.Fatal("ran outside budget")
	}
}
func TestResearchRestrictedDiagnosticRejectsWrongObservedRoute(t *testing.T) {
	now := time.Now()
	c := &ExactNodeChecker{serviceProbe: func(context.Context, string, string, string, catalog.Service) (evidence.ProbeEvidence, error) {
		return evidence.ProbeEvidence{SchemaVersion: evidence.ProbeSchemaVersion, Outcome: evidence.OutcomeServiceAccepted, HTTPStatus: 200, Service: "telegram", ProbeID: "proof", StartedAt: now.Add(-time.Second), FinishedAt: now, Verdict: evidence.VerdictPass, RoutePathID: "direct", ExpectedRoutePathID: "direct", ObservedRoutePathID: "direct"}, nil
	}}
	r := NodeCheckResult{RoutePathID: "sing-box:node-a"}
	c.probeRestrictedDiagnostic(context.Background(), &r, "", "", catalog.Service{})
	if r.Stages[0].Status != "unknown" || r.Available {
		t.Fatal("wrong identity promoted")
	}
}
