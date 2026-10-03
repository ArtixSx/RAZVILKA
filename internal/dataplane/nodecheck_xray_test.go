package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

const xrayNodeMaterial = `{"type":"vless","server":"node.example","server_port":443,"uuid":"123e4567-e89b-12d3-a456-426614174000","tls":{"enabled":true,"server_name":"front.example","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"KEY","short_id":"abcd"}}}`

func xrayCheckedRequest() NodeCheckRequest {
	r := checkedNodeRequest()
	r.Outbound = []byte(xrayNodeMaterial)
	r.Service.Strategy = []string{"xray"}
	return r
}

func fakeExactXrayChecker(t *testing.T) *ExactNodeChecker {
	c := fakeExactNodeChecker(t)
	c.engine = "xray"
	probe := c.serviceProbe
	c.serviceProbe = func(ctx context.Context, address, route, egress string, svc catalog.Service) (evidence.ProbeEvidence, error) {
		p, err := probe(ctx, address, route, egress, svc)
		p.RoutePathID, p.ExpectedRoutePathID, p.ObservedRoutePathID, p.Engine = route, route, route, "xray"
		return p, err
	}
	c.serviceIPProbe = func(ctx context.Context, address, route, egress string, svc catalog.Service, _ netip.Addr) (evidence.ProbeEvidence, error) {
		return c.serviceProbe(ctx, address, route, egress, svc)
	}
	return c
}

func TestExactXrayConstructorOwnsIndependentSlots(t *testing.T) {
	x := NewExactXrayNodeCheckerSlots(t.TempDir(), 3)
	s := NewExactNodeCheckerSlots(t.TempDir(), MaxExactNodeSlots)
	if x.EngineID() != "xray" || s.EngineID() != "sing-box" || x.Capacity() != 3 || x.Port < s.Port+MaxExactNodeSlots {
		t.Fatal("engines overlap or identity changed")
	}
	for slot := range MaxExactNodeSlots {
		v := x.session(slot)
		if !strings.HasPrefix(v.Spec.ID, "node-check-xray") || len(v.Spec.Args) != 3 || v.Spec.Args[1] != "-config" || !v.Spec.RouteProof || v.Port != x.Port+slot {
			t.Fatalf("wrong Xray slot: %+v", v)
		}
	}
}

func TestExactXrayPreservesPathAndSuccessfulPin(t *testing.T) {
	c := fakeExactXrayChecker(t)
	first, second := netip.MustParseAddr("203.0.113.8"), netip.MustParseAddr("203.0.113.9")
	c.resolve = func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{first, second}, nil }
	c.dialTransport = func(_ context.Context, _ exactNodeEndpoint, ips []netip.Addr) (bool, error) {
		if ips[0] == first {
			return true, errors.New("closed")
		}
		return true, nil
	}
	c.prepare = func(_ context.Context, s exactNodeSession, _ NodeCheckRequest, e exactNodeEndpoint) (exactNodeSession, error) {
		if e.Pinned != second || !strings.HasPrefix(s.Spec.ID, "node-check-xray") {
			t.Fatal("lost exact slot or successful pin")
		}
		return s, nil
	}
	r, err := c.Check(context.Background(), xrayCheckedRequest())
	if err != nil || !r.Available || r.RoutePathID != "xray:"+checkedNodeID || r.Evidence.Engine != "xray" {
		t.Fatalf("wrong proof: %+v %v", r, err)
	}
}

func TestExactXrayUnsupportedIsLocalBeforeDNSOrSlots(t *testing.T) {
	for _, extra := range []string{`,"transport":{"type":"xhttp"}`, `,"multiplex":{"enabled":true}`, `,"detour":"other"`} {
		c := fakeExactXrayChecker(t)
		c.resolve = func(context.Context, string) ([]netip.Addr, error) {
			t.Fatal("unsupported profile reached DNS")
			return nil, nil
		}
		r := xrayCheckedRequest()
		r.Outbound = []byte(strings.TrimSuffix(xrayNodeMaterial, "}") + extra + "}")
		result, err := c.Check(context.Background(), r)
		if !errors.Is(err, ErrExactNodeUnsupported) || result.ProbeID != "" || len(c.gate) != 1 {
			t.Fatalf("local error could enter reputation: %+v %v", result, err)
		}
	}
}

func TestExactXrayRequiresControlAndFinalRuntimeIdentity(t *testing.T) {
	for _, mode := range []string{"leak", "missing-control", "restart"} {
		t.Run(mode, func(t *testing.T) {
			c := fakeExactXrayChecker(t)
			switch mode {
			case "leak":
				c.directEgress = func(context.Context) (string, error) { return "2001:db8::20", nil }
			case "missing-control":
				c.directEgress = func(context.Context) (string, error) { return "", errors.New("offline") }
			case "restart":
				calls := 0
				c.identity = func(exactNodeSession) (routeidentity.Passport, error) {
					calls++
					return routeidentity.Passport{ID: "owned", Outbound: "vless", PID: calls}, nil
				}
			}
			r, err := c.Check(context.Background(), xrayCheckedRequest())
			if err != nil || r.Available || r.Verdict == evidence.VerdictPass || r.EgressIP != "" {
				t.Fatalf("guard bypassed: %+v %v", r, err)
			}
		})
	}
}
