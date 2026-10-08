package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/strategylab"
)

func nfqwsScopedSelectedFixture(t *testing.T) (Plan, NFQWSScopedSpec) {
	t.Helper()
	plan, spec, _ := nfqwsScopedFixture(t)
	route := &plan.Routes[0]
	route.LogicalServiceID, route.ServiceID, route.NetworkPolicyRole = "ip-service", "network-exact-cell", "override"
	route.Sources, route.CIDRs = []string{"192.168.1.0/24"}, []string{"8.8.8.8/32", "1.1.1.1/32"}
	spec.Candidate.ServiceID, spec.Candidate.IPFamily = "ip-service", "ipv4"
	spec.Candidate.Traffic = []NFQWSScopedTraffic{{Protocol: "tcp", First: 80, Last: 80}, {Protocol: "tcp", First: 443, Last: 443}}
	for index, destination := range route.CIDRs {
		traffic := spec.Candidate.Traffic[index]
		spec.Matches = append(spec.Matches, NFQWSScopedMatch{ServiceID: "ip-service", Origin: "override", Route: "nfqws2", Ingress: "br0",
			Source: netip.MustParsePrefix(route.Sources[0]), Destination: netip.MustParsePrefix(destination), Protocol: traffic.Protocol, FirstPort: traffic.First, LastPort: traffic.Last})
	}
	return plan, spec
}

func TestNFQWSScopedSelectedCompilerPreservesExactTuplesWithoutCrossProduct(t *testing.T) {
	plan, spec := nfqwsScopedSelectedFixture(t)
	p, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil {
		t.Fatal(err)
	}
	effects, err := p.Effects()
	if err != nil {
		t.Fatal(err)
	}
	var captures []string
	for _, effect := range effects.Effects {
		line := strings.Join(effect.Add, " ")
		if strings.Contains(line, "NFQUEUE") {
			captures = append(captures, line)
			if effect.Tool != PolicyEffectIPTables || !strings.Contains(line, "--mark 0x20000000/0x28000000") || !strings.Contains(line, "-i br0 -s 192.168.1.0/24") {
				t.Fatal("tuple escaped original LAN/family", line)
			}
		}
	}
	if len(captures) != 2 || !strings.Contains(strings.Join(captures, "\n"), "-d 8.8.8.8/32 -m mark --mark") || !strings.Contains(captures[0]+captures[1], "--dport 80") {
		t.Fatal("exact selected cells missing", captures)
	}
	for _, line := range captures {
		if strings.Contains(line, "-d 8.8.8.8/32") && !strings.Contains(line, "--dport 80 ") || strings.Contains(line, "-d 1.1.1.1/32") && !strings.Contains(line, "--dport 443 ") || strings.Contains(line, "-p udp") {
			t.Fatal("generic route expanded candidate coverage", line)
		}
	}
	slices.Reverse(spec.Matches)
	p2, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil || p2.Digest() != p.Digest() {
		t.Fatal("tuple order changed immutable effect identity", err)
	}
	copy := p.Spec()
	copy.Matches[0].FirstPort = 1
	copy.Candidate.Traffic[0].First = 1
	if p.Spec().Matches[0].FirstPort == 1 || p.Spec().Candidate.Traffic[0].First == 1 {
		t.Fatal("detached tuple changed retained compiler input")
	}
}

func TestNFQWSScopedSelectedCompilerRejectsLostOrForeignTuple(t *testing.T) {
	for name, change := range map[string]func(*Plan, *NFQWSScopedSpec){
		"no exact tuples":         func(_ *Plan, s *NFQWSScopedSpec) { s.Matches = nil },
		"no source family":        func(_ *Plan, s *NFQWSScopedSpec) { s.Candidate.IPFamily = "" },
		"source family changed":   func(_ *Plan, s *NFQWSScopedSpec) { s.Candidate.IPFamily = "ipv6" },
		"foreign logical service": func(p *Plan, _ *NFQWSScopedSpec) { p.Routes[0].LogicalServiceID = "other-service" },
		"second NFQ service": func(p *Plan, _ *NFQWSScopedSpec) {
			r := p.Routes[0]
			r.LogicalServiceID = "other-service"
			p.Routes = append(p.Routes, r)
		},
		"foreign tuple service":    func(_ *Plan, s *NFQWSScopedSpec) { s.Matches[0].ServiceID = "other-service" },
		"foreign origin":           func(_ *Plan, s *NFQWSScopedSpec) { s.Matches[0].Origin = "catchall" },
		"foreign route role":       func(p *Plan, _ *NFQWSScopedSpec) { p.Routes[0].NetworkPolicyRole = "catchall" },
		"foreign path":             func(_ *Plan, s *NFQWSScopedSpec) { s.Matches[0].Route = "nfqws2:foreign" },
		"foreign ingress":          func(_ *Plan, s *NFQWSScopedSpec) { s.Matches[0].Ingress = "br-other" },
		"source expanded":          func(_ *Plan, s *NFQWSScopedSpec) { s.Matches[0].Source = netip.MustParsePrefix("192.168.0.0/16") },
		"destination expanded":     func(_ *Plan, s *NFQWSScopedSpec) { s.Matches[0].Destination = netip.MustParsePrefix("8.8.8.0/24") },
		"mixed family route":       func(p *Plan, _ *NFQWSScopedSpec) { p.Routes[0].CIDRs = append(p.Routes[0].CIDRs, "2606:4700::/32") },
		"ports widened":            func(_ *Plan, s *NFQWSScopedSpec) { s.Matches[0].LastPort = 443 },
		"native transport changed": func(_ *Plan, s *NFQWSScopedSpec) { s.Matches[0].Protocol = "udp" },
		"uncovered cell":           func(_ *Plan, s *NFQWSScopedSpec) { s.Matches = s.Matches[:1] },
		"duplicate tuple":          func(_ *Plan, s *NFQWSScopedSpec) { s.Matches = append(s.Matches, s.Matches[0]) },
		"domain substitution":      func(p *Plan, _ *NFQWSScopedSpec) { p.Routes[0].Domains = []string{"example.com"} },
		"excess tuples":            func(_ *Plan, s *NFQWSScopedSpec) { s.Matches = make([]NFQWSScopedMatch, 1025) },
	} {
		t.Run(name, func(t *testing.T) {
			plan, spec := nfqwsScopedSelectedFixture(t)
			change(&plan, &spec)
			if _, err := CompileNFQWSScopedPlan(plan, spec); !errors.Is(err, ErrNFQWSScopedOwner) {
				t.Fatal("incomplete/foreign tuple acquired compiler output", err)
			}
		})
	}
}

func TestNFQWSScopedSelectedCompilerQUICIPv6DoesNotExpandIPv4OrTCP(t *testing.T) {
	plan, spec := nfqwsScopedSelectedFixture(t)
	plan.Routes[0].Sources, plan.Routes[0].CIDRs = []string{"fd00:1::/64"}, []string{"2606:4700::/32"}
	spec.Candidate.IPFamily = "ipv6"
	spec.Candidate.Traffic = []NFQWSScopedTraffic{{Protocol: "udp", First: 443, Last: 443}}
	spec.Matches = []NFQWSScopedMatch{{ServiceID: "ip-service", Origin: "override", Route: "nfqws2", Ingress: "br0", Source: netip.MustParsePrefix("fd00:1::/64"), Destination: netip.MustParsePrefix("2606:4700::/32"), Protocol: "udp", FirstPort: 443, LastPort: 443}}
	p, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.chains) != 1 || p.chains[0].tool != PolicyEffectIP6Tables || len(p.chains[0].body) != 1 || !strings.Contains(strings.Join(p.chains[0].body[0], " "), "-p udp -m udp --dport 443") {
		t.Fatal("saved QUIC family/transport expanded")
	}
}

func TestNFQWSScopedSelectionRequiresActualOriginalSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	plan, spec := nfqwsScopedSelectedFixture(t)
	matches := slices.Clone(spec.Matches)
	spec.Matches, spec.Candidate.ServiceID, spec.Candidate.IPFamily = nil, "", ""
	for _, source := range []*strategylab.SelectedCandidateReview{nil, {}} {
		if got, err := ReviewNFQWSScopedSelection(ctx, source, strategylab.SelectedCandidateReference{}, plan, spec, matches); got != nil || err == nil {
			t.Fatal("detached source manufactured a selected consumer")
		}
	}
	var zero NFQWSScopedSelection
	if zero.Current(ctx) == nil || zero.Close() == nil || len(zero.Spec().Matches) != 0 {
		t.Fatal("zero consumer accepted")
	}
	original := &NFQWSScopedSelection{spec: spec}
	original.self = original
	var copy NFQWSScopedSelection
	reflect.ValueOf(&copy).Elem().Set(reflect.ValueOf(original).Elem())
	if copy.Current(ctx) == nil || copy.Close() == nil || copy.Spec().Queue != 0 {
		t.Fatal("copied consumer accepted")
	}
}

func TestNFQWSScopedSelectedExecutionRetainsFullTuplesAndRefusesTampering(t *testing.T) {
	plan, spec := nfqwsScopedSelectedFixture(t)
	plan.PlanID = "dp-0123456789abcdef"
	p, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil {
		t.Fatal(err)
	}
	e := executionNFQWSResourceFixture(t, "planned")
	r := &e.Resources[0]
	r.EffectsDigest = p.Digest()
	r.Generation = p.Resources().Generation
	r.NFQWS.Plan, r.NFQWS.Spec = cloneExecutionResourcePlan(plan), p.Spec()
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var read Execution
	if err := json.Unmarshal(data, &read); err != nil || validateExecutionResources(read, false) != nil {
		t.Fatal("exact tuple lost in SAME retained Execution", err)
	}
	if err := validateExecutionResources(read, true); !errors.Is(err, ErrExecutionJournal) {
		t.Fatal("comparison record manufactured terminal active authority", err)
	}
	for name, change := range map[string]func(*Execution){
		"tuple port":     func(e *Execution) { e.Resources[0].NFQWS.Spec.Matches[0].FirstPort = 81 },
		"tuple missing":  func(e *Execution) { e.Resources[0].NFQWS.Spec.Matches = nil },
		"family missing": func(e *Execution) { e.Resources[0].NFQWS.Spec.Candidate.IPFamily = "" },
		"full metadata swapped with old compiler": func(e *Execution) {
			s := e.Resources[0].NFQWS.Spec.Clone()
			s.Matches, s.Candidate.ServiceID, s.Candidate.IPFamily = nil, "", ""
			e.Resources[0].NFQWS.Spec = s
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := e
			changed.Resources = cloneExecutionResources(e.Resources)
			change(&changed)
			if !errors.Is(validateExecutionResources(changed, false), ErrExecutionJournal) {
				t.Fatal("changed record retained its original effects identity")
			}
		})
	}
	detached := cloneExecutionResources(e.Resources)
	detached[0].NFQWS.Spec.Matches[0].FirstPort = 1
	if validateExecutionResources(e, false) != nil {
		t.Fatal("detached retained tuple aliased original journal input")
	}
}
