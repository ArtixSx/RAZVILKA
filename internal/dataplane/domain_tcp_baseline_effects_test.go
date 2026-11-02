package dataplane

import (
	"net/netip"
	"slices"
	"testing"
)

func TestDomainTCPBaselineFlowCompilerPreservesOriginalTuple(t *testing.T) {
	_, capture := domainTCPBaselineKernelModel(t)
	s := domainTCPBaselineFlowSpec{Capture: capture, Source: netip.AddrPortFrom(capture.Client.Address, 49123), Target: netip.AddrPortFrom(capture.Xray.RealIP, 443), Egress: "wan0"}
	p, err := compileDomainTCPBaselineFlow(s)
	if err != nil || len(p.Effects) != 5 {
		t.Fatal(p, err)
	}
	for i, e := range p.Effects {
		if i >= 2 && (!slices.Contains(e.Add, "49123") || !slices.Contains(e.Add, "443") || !slices.Contains(e.Add, s.Source.Addr().String()+"/32") || !slices.Contains(e.Add, s.Target.Addr().String()+"/32")) {
			t.Fatalf("unbound effect%d: %v", i, e)
		}
		if i > 0 && len(e.Needs) != i {
			t.Fatalf("missing prerequisites%d: %v", i, e.Needs)
		}
	}
	for _, mutate := range []func(*domainTCPBaselineFlowSpec){
		func(s *domainTCPBaselineFlowSpec) { s.Source = netip.MustParseAddrPort("192.168.1.99:49123") },
		func(s *domainTCPBaselineFlowSpec) { s.Target = netip.MustParseAddrPort("127.0.0.1:443") },
		func(s *domainTCPBaselineFlowSpec) { s.Target = netip.AddrPortFrom(s.Target.Addr(), 8443) },
		func(s *domainTCPBaselineFlowSpec) { s.Egress = s.Capture.Client.Interface },
		func(s *domainTCPBaselineFlowSpec) { s.Egress = "lo" },
	} {
		bad := s
		mutate(&bad)
		if _, err := compileDomainTCPBaselineFlow(bad); err == nil {
			t.Fatal("accepted unbound flow", bad)
		}
	}
}
