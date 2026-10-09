package dataplane

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func nfqwsScopedDirectFixture(t *testing.T, family string) (Plan, NFQWSScopedSpec, *NFQWSScopedPlan) {
	t.Helper()
	plan, spec := nfqwsScopedSelectedFixture(t)
	gate := &plan.LAN.Ingress[0]
	gate.Membership = "mac"
	gate.IncludedMACs = []string{"02:00:00:00:00:11", "02:00:00:00:00:22"}
	gate.ExcludedMACs = []string{"02:00:00:00:00:11"}
	gate.Sources = []string{"192.168.1.0/24"}
	gate.ExcludedSources = []string{"192.168.1.64/26"}
	plan.Routes[0].CIDRs = []string{"8.8.8.0/25", "8.8.8.192/26"}
	if family == "ipv6" {
		gate.Sources, gate.ExcludedSources = []string{"fd00:1::/64"}, []string{"fd00:1::40/122"}
		plan.Routes[0].Sources = slices.Clone(gate.Sources)
		plan.Routes[0].CIDRs = []string{"2001:4860::/34", "2001:4860:c000::/34"}
	}
	spec.Candidate.IPFamily = family
	for i := range spec.Matches {
		spec.Matches[i].Source = netip.MustParsePrefix(gate.Sources[0])
		spec.Matches[i].Destination = netip.MustParsePrefix(plan.Routes[0].CIDRs[i])
	}
	lan, err := CompileNFQWSDirectLANPolicyRuntime(plan.LAN.Generation, plan.LAN.Ingress)
	if err != nil {
		t.Fatal(err)
	}
	plan.LAN = lan
	p, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil {
		t.Fatal(err)
	}
	return plan, spec, p
}

// This evaluates only frozen selector predicates, not kernel traffic or a
// native owner. The matrix independently states desired eligibility/baseline.
type nfqwsDirectFlow struct {
	hook, ingress, source, destination, mac, protocol string
	port                                              uint16
	mark                                              uint32
}

func nfqwsDirectCaptures(t *testing.T, p *NFQWSScopedPlan, flow nfqwsDirectFlow) bool {
	t.Helper()
	if flow.hook != "FORWARD" {
		return false
	}
	for _, chain := range p.chains {
		for _, jump := range chain.jumps {
			if !nfqwsDirectMatches(t, jump, flow) {
				continue
			}
			for _, rule := range chain.body {
				if !nfqwsDirectMatches(t, rule, flow) {
					continue
				}
				if slices.Contains(rule, "RETURN") {
					break
				}
				if slices.Contains(rule, "NFQUEUE") {
					return true
				}
			}
		}
	}
	return false
}

func nfqwsDirectMatches(t *testing.T, rule []string, flow nfqwsDirectFlow) bool {
	t.Helper()
	for i := 0; i < len(rule); i += 2 {
		key, value := rule[i], rule[i+1]
		switch key {
		case "-i":
			if flow.ingress != value {
				return false
			}
		case "-s", "-d":
			address := flow.source
			if key == "-d" {
				address = flow.destination
			}
			if !netip.MustParsePrefix(value).Contains(netip.MustParseAddr(address)) {
				return false
			}
		case "--mac-source":
			if !strings.EqualFold(flow.mac, value) {
				return false
			}
		case "-p":
			if flow.protocol != value {
				return false
			}
		case "--dport":
			first, last, ranged := strings.Cut(value, ":")
			lo, err := strconv.Atoi(first)
			if err != nil {
				t.Fatal(err)
			}
			hi := lo
			if ranged {
				hi, err = strconv.Atoi(last)
				if err != nil {
					t.Fatal(err)
				}
			}
			if int(flow.port) < lo || int(flow.port) > hi {
				return false
			}
		case "-m", "-j", "--queue-num":
		default:
			t.Fatal("model encountered an unreviewed predicate", key)
		}
	}
	return true
}

func TestNFQWSScopedDirectSelectorEligibilityAndNegativePrecedence(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) {
			_, _, p := nfqwsScopedDirectFixture(t, family)
			allowed := nfqwsDirectFlow{hook: "FORWARD", ingress: "br0", source: "192.168.1.10", destination: "8.8.8.1", mac: "02:00:00:00:00:22", protocol: "tcp", port: 80}
			excludedSource, manual, russian, otherPositive := "192.168.1.65", "8.8.8.130", "8.8.8.170", "8.8.8.200"
			if family == "ipv6" {
				allowed.source, allowed.destination = "fd00:1::10", "2001:4860::1"
				excludedSource, manual, russian, otherPositive = "fd00:1::41", "2001:4860:4000::1", "2001:4860:8000::1", "2001:4860:c000::1"
			}
			for _, row := range []struct {
				name   string
				change func(*nfqwsDirectFlow)
				want   bool
			}{
				{"eligible", func(*nfqwsDirectFlow) {}, true},
				{"excluded MAC at new address", func(f *nfqwsDirectFlow) { f.mac = "02:00:00:00:00:11" }, false},
				{"excluded source", func(f *nfqwsDirectFlow) { f.source = excludedSource }, false},
				{"unknown MAC", func(f *nfqwsDirectFlow) { f.mac = "02:00:00:00:00:33" }, false},
				{"missing MAC", func(f *nfqwsDirectFlow) { f.mac = "" }, false},
				{"wrong ingress", func(f *nfqwsDirectFlow) { f.ingress = "br9" }, false},
				{"outside source", func(f *nfqwsDirectFlow) { f.source = "192.168.2.10" }, false},
				// These frozen positive cells have already had the manual/RU
				// destination ranges removed by DEFAULT. No enclosing CIDR is
				// reconstructed, including when another native port is eligible.
				{"manual destination gap", func(f *nfqwsDirectFlow) { f.destination = manual }, false},
				{"Russian destination gap", func(f *nfqwsDirectFlow) { f.destination = russian; f.port = 443 }, false},
				{"unlisted destination", func(f *nfqwsDirectFlow) { f.destination = "1.1.1.1" }, false},
				{"destination port cross product", func(f *nfqwsDirectFlow) { f.port = 443 }, false},
				{"second exact tuple", func(f *nfqwsDirectFlow) { f.destination = otherPositive; f.port = 443 }, true},
				{"foreign transport", func(f *nfqwsDirectFlow) { f.protocol = "udp" }, false},
				{"router generated OUTPUT", func(f *nfqwsDirectFlow) { f.hook = "OUTPUT"; f.mark = 0x40000000 }, false},
			} {
				t.Run(row.name, func(t *testing.T) {
					flow := allowed
					row.change(&flow)
					// Stale/foreign admission marks neither grant scope nor clear
					// any negative. Direct predicates never read or change them.
					for _, mark := range []uint32{0, LANPolicyManagedMark, LANPolicyBypassMark, 0x40000000, 0xffffffff} {
						flow.mark = mark
						if got := nfqwsDirectCaptures(t, p, flow); got != row.want {
							t.Fatal("wrong frozen eligibility", got, row.want, flow)
						}
					}
				})
			}
		})
	}
}

func TestNFQWSScopedDirectSelectorPortRangeBoundaries(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			plan, spec, _ := nfqwsScopedDirectFixture(t, "ipv4")
			spec.Candidate.Traffic = []NFQWSScopedTraffic{{Protocol: protocol, First: 443, Last: 445}}
			for i := range spec.Matches {
				spec.Matches[i].Protocol, spec.Matches[i].FirstPort, spec.Matches[i].LastPort = protocol, 443, 445
			}
			p, err := CompileNFQWSScopedPlan(plan, spec)
			if err != nil {
				t.Fatal(err)
			}
			flow := nfqwsDirectFlow{hook: "FORWARD", ingress: "br0", source: "192.168.1.10", destination: "8.8.8.1", mac: "02:00:00:00:00:22", protocol: protocol}
			for _, port := range []uint16{442, 443, 444, 445, 446} {
				flow.port = port
				if got := nfqwsDirectCaptures(t, p, flow); got != (port >= 443 && port <= 445) {
					t.Fatal("port interval widened or lost an endpoint", protocol, port, got)
				}
			}
		})
	}
}

func TestNFQWSScopedDirectSelectorIngressNegativesDoNotLeakAndRemainFirst(t *testing.T) {
	plan, spec, _ := nfqwsScopedDirectFixture(t, "ipv4")
	plan.LAN.Ingress[0].ExcludedSources = append(plan.LAN.Ingress[0].ExcludedSources, "192.168.2.0/24")
	gate := plan.LAN.Ingress[0]
	gate.SegmentID, gate.Interface = "other-LAN", "br1"
	gate.Sources, gate.ExcludedSources, gate.ExcludedMACs = []string{"192.168.2.0/24"}, nil, nil
	gate.IncludedMACs = []string{"02:00:00:00:00:11"}
	plan.LAN.Ingress = append(plan.LAN.Ingress, gate)
	var err error
	plan.LAN, err = CompileNFQWSDirectLANPolicyRuntime(plan.LAN.Generation, plan.LAN.Ingress)
	if err != nil {
		t.Fatal(err)
	}
	route := plan.Routes[0]
	route.Ingress, route.Sources = []string{"br1"}, slices.Clone(gate.Sources)
	plan.Routes = append(plan.Routes, route)
	for _, match := range slices.Clone(spec.Matches) {
		match.Ingress, match.Source = "br1", netip.MustParsePrefix(gate.Sources[0])
		spec.Matches = append(spec.Matches, match)
	}
	p, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil {
		t.Fatal(err)
	}
	flow := nfqwsDirectFlow{hook: "FORWARD", ingress: "br1", source: "192.168.2.10", destination: "8.8.8.1", mac: "02:00:00:00:00:11", protocol: "tcp", port: 80}
	if !nfqwsDirectCaptures(t, p, flow) {
		t.Fatal("another ingress inherited br0's negative source/MAC")
	}
	if len(p.chains) != 1 {
		t.Fatal("negative-only family acquired a native attachment")
	}
	for _, chain := range p.chains {
		positive := false
		for _, rule := range chain.body {
			if slices.Contains(rule, "NFQUEUE") {
				positive = true
			} else if positive || !slices.Contains(rule, "RETURN") || !slices.Contains(rule, "-i") {
				t.Fatal("negative is late or unscoped", rule)
			}
		}
		for _, jump := range chain.jumps {
			if !slices.Contains(jump, "-i") || !slices.Contains(jump, "-s") || !slices.Contains(jump, "--mac-source") {
				t.Fatal("attachment broadened physical membership", jump)
			}
		}
	}
	effects, err := p.Effects()
	if err != nil {
		t.Fatal(err)
	}
	for _, effect := range effects.Effects {
		for _, forbidden := range []string{"--mark", "MARK", "CONNMARK", "OUTPUT", "PREROUTING", "--queue-bypass"} {
			if slices.Contains(effect.Add, forbidden) || effect.Tool == PolicyEffectIP {
				t.Fatal("direct scope gained unrelated kernel effects", effect)
			}
		}
	}
}

func TestNFQWSScopedDirectSelectorAllMembershipStillHonorsMACNegatives(t *testing.T) {
	plan, spec, _ := nfqwsScopedDirectFixture(t, "ipv4")
	plan.LAN.Ingress[0].Membership, plan.LAN.Ingress[0].IncludedMACs = "all", nil
	var err error
	plan.LAN, err = CompileNFQWSDirectLANPolicyRuntime(plan.LAN.Generation, plan.LAN.Ingress)
	if err != nil {
		t.Fatal(err)
	}
	p, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil {
		t.Fatal(err)
	}
	flow := nfqwsDirectFlow{hook: "FORWARD", ingress: "br0", source: "192.168.1.10", destination: "8.8.8.1", mac: "02:00:00:00:00:33", protocol: "tcp", port: 80}
	if !nfqwsDirectCaptures(t, p, flow) {
		t.Fatal("reviewed all membership became a saved-device list")
	}
	flow.mac = "02:00:00:00:00:11"
	if nfqwsDirectCaptures(t, p, flow) {
		t.Fatal("excluded device's new address entered the queue")
	}
}

func TestNFQWSScopedDirectSelectorRefusesMissingForeignAndOversizedInput(t *testing.T) {
	for _, kind := range []string{"no tuples", "lost tuple", "foreign port", "other consumer", "domain", "MAC product"} {
		t.Run(kind, func(t *testing.T) {
			plan, spec, _ := nfqwsScopedDirectFixture(t, "ipv4")
			switch kind {
			case "no tuples":
				spec.Matches = nil
				spec.Candidate.ServiceID, spec.Candidate.IPFamily = "", ""
			case "lost tuple":
				spec.Matches = spec.Matches[:1]
			case "foreign port":
				spec.Matches[0].LastPort++
			case "other consumer":
				route := plan.Routes[0]
				route.Resolved = "xray:node"
				plan.Routes = append(plan.Routes, route)
			case "domain":
				plan.Routes[0].Domains = []string{"example.com"}
			case "MAC product":
				gate := &plan.LAN.Ingress[0]
				gate.IncludedMACs = nil
				for i := 0; i < 512; i++ {
					gate.IncludedMACs = append(gate.IncludedMACs, "02:00:00:00:"+nfqwsDirectHexByte(i/256)+":"+nfqwsDirectHexByte(i%256))
				}
				var err error
				plan.LAN, err = CompileNFQWSDirectLANPolicyRuntime(plan.LAN.Generation, plan.LAN.Ingress)
				if err != nil {
					t.Fatal(err)
				}
				spec.Candidate.Traffic = nil
				spec.Matches = nil
				for port := uint16(80); port < 85; port++ {
					spec.Candidate.Traffic = append(spec.Candidate.Traffic, NFQWSScopedTraffic{Protocol: "tcp", First: port, Last: port})
					for _, destination := range plan.Routes[0].CIDRs {
						spec.Matches = append(spec.Matches, NFQWSScopedMatch{ServiceID: spec.Candidate.ServiceID, Origin: "override", Route: "nfqws2", Ingress: "br0", Source: netip.MustParsePrefix(gate.Sources[0]), Destination: netip.MustParsePrefix(destination), Protocol: "tcp", FirstPort: port, LastPort: port})
					}
				}
			}
			if p, err := CompileNFQWSScopedPlan(plan, spec); err == nil || p != nil {
				t.Fatal("invalid or incomplete input compiled", kind)
			}
		})
	}
}

func nfqwsDirectHexByte(value int) string {
	text := strconv.FormatInt(int64(value), 16)
	if len(text) == 1 {
		text = "0" + text
	}
	return strings.ToUpper(text)
}

func TestNFQWSScopedDirectSelectorFreezesCompleteIdentityAndCanonicalOrder(t *testing.T) {
	plan, spec, p := nfqwsScopedDirectFixture(t, "ipv4")
	before := p.Digest()
	slices.Reverse(spec.Matches)
	slices.Reverse(plan.LAN.Ingress[0].IncludedMACs)
	var err error
	plan.LAN, err = CompileNFQWSDirectLANPolicyRuntime(plan.LAN.Generation, plan.LAN.Ingress)
	if err != nil {
		t.Fatal(err)
	}
	other, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil || other.Digest() != before {
		t.Fatal("equivalent frozen order changed identity", err)
	}
	copy := p.Spec()
	copy.Matches[0].LastPort++
	plan.LAN.Ingress[0].IncludedMACs[0] = "02:00:00:00:00:44"
	if p.Digest() != before || p.Spec().Matches[0].LastPort == copy.Matches[0].LastPort || p.lan.Ingress[0].IncludedMACs[0] == "02:00:00:00:00:44" {
		t.Fatal("detached input changed the original compilation")
	}
	plan, spec, _ = nfqwsScopedDirectFixture(t, "ipv4")
	legacy, err := CompileLANPolicyRuntime(plan.LAN.Generation, plan.LAN.Ingress)
	if err != nil {
		t.Fatal(err)
	}
	plan.LAN = legacy
	marked, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil || marked.Digest() == before || slices.Equal(marked.Resources().Chains, p.Resources().Chains) {
		t.Fatal("direct and marked modes share executable identity", err)
	}
}
