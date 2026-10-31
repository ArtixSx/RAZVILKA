package dataplane

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func nfqwsProbePlanFixture(t *testing.T) (Plan, NFQWSScopedSpec) {
	t.Helper()
	p, s, _ := nfqwsScopedFixture(t)
	p.LAN = nil
	p.Routes = []Route{{ServiceID: "service", Resolved: "nfqws2", CIDRs: []string{"8.8.8.8/32"}}}
	s.Queue = 200
	s.Candidate.ServiceID = "service"
	s.Candidate.IPFamily = "ipv4"
	s.Candidate.Traffic = []NFQWSScopedTraffic{{Protocol: "tcp", First: 443, Last: 443}}
	s.NetworkIdentity = &netidentity.Identity{Version: netidentity.Version, Kind: netidentity.ProcNetInode, BootID: s.BootID, Inode: 12345}
	s.Probe = &NFQWSProbeSpec{Source: netip.MustParseAddrPort("192.168.1.1:35001"), Destination: netip.MustParseAddrPort("8.8.8.8:443"), SocketDevice: 9, SocketInode: 123, Epoch: strings.Repeat("1", 32), ValidationGeneration: strings.Repeat("2", 32), CriteriaDigest: strings.Repeat("3", 64)}
	return p, s
}

func TestNFQWSProbeCompilerExactOutputSocket(t *testing.T) {
	p, s := nfqwsProbePlanFixture(t)
	compiled, err := CompileNFQWSScopedPlan(p, s)
	if err != nil {
		t.Fatal(err)
	}
	effects, err := compiled.Effects()
	if err != nil {
		t.Fatal(err)
	}
	if compiled.lan != nil || compiled.Resources().LANDigest != "" || len(effects.Effects) != 3 {
		t.Fatal("probe invented LAN or broad effects")
	}
	for _, e := range effects.Effects[1:] {
		row := strings.Join(e.Add, " ")
		for _, value := range []string{"-s 192.168.1.1/32", "-d 8.8.8.8/32", "--sport 35001", "--dport 443", "--mark 0x0/0xffffffff"} {
			if !strings.Contains(row, value) {
				t.Fatal("unbound capture", row)
			}
		}
		if strings.Contains(row, "FORWARD") || strings.Contains(row, "--queue-bypass") {
			t.Fatal(row)
		}
	}
	if effects.Effects[2].Add[3] != "OUTPUT" {
		t.Fatal("router probe targets transit")
	}
	s.Probe.Source = netip.MustParseAddrPort("192.168.1.1:35002")
	other, err := CompileNFQWSScopedPlan(p, s)
	if err != nil || other.Digest() == compiled.Digest() {
		t.Fatal("different kernel port retained identity", err)
	}
	detached := compiled.Spec()
	detached.Probe.SocketInode++
	if reflect.DeepEqual(detached, compiled.Spec()) {
		t.Fatal("spec aliases probe metadata")
	}
	if _, err := AcquireNFQWSExecutionResource(context.Background(), compiled.Spec()); err == nil {
		t.Fatal("typed socket metadata granted execution")
	}
}

func TestNFQWSProbeCompilerRejectsScopeExpansion(t *testing.T) {
	for name, mutate := range map[string]func(*Plan, *NFQWSScopedSpec){
		"LAN":           func(p *Plan, s *NFQWSScopedSpec) { p.LAN = lanRuntimeFixture(t) },
		"queue":         func(p *Plan, s *NFQWSScopedSpec) { s.Queue = 201 },
		"port":          func(p *Plan, s *NFQWSScopedSpec) { s.Probe.Destination = netip.MustParseAddrPort("8.8.8.8:80") },
		"private":       func(p *Plan, s *NFQWSScopedSpec) { s.Probe.Destination = netip.MustParseAddrPort("192.168.1.2:443") },
		"domain":        func(p *Plan, s *NFQWSScopedSpec) { p.Routes[0].Domains = []string{"example.com"} },
		"transit":       func(p *Plan, s *NFQWSScopedSpec) { p.Routes[0].Ingress = []string{"br0"} },
		"unknownsocket": func(p *Plan, s *NFQWSScopedSpec) { s.Probe.SocketInode = 0 },
		"cidr":          func(p *Plan, s *NFQWSScopedSpec) { p.Routes[0].CIDRs = []string{"8.8.8.0/24"} },
		"UDP":           func(p *Plan, s *NFQWSScopedSpec) { s.Candidate.Traffic[0].Protocol = "udp" },
	} {
		t.Run(name, func(t *testing.T) {
			p, s := nfqwsProbePlanFixture(t)
			mutate(&p, &s)
			if _, err := CompileNFQWSScopedPlan(p, s); err == nil {
				t.Fatal("expanded scope accepted")
			}
		})
	}
}
