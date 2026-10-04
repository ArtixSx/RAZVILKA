package dataplane

import (
	"strings"
	"testing"
	"time"
)

func networkPolicyLANFixture(t *testing.T) Input {
	t.Helper()
	generation := strings.Repeat("a", 64)
	lan, err := CompileLANPolicyRuntime(generation, []LANPolicyIngress{{
		SegmentID: "home", Interface: "br0", Sources: []string{"192.168.1.0/24", "fd00::/64"},
		Membership: "mac", IncludedMACs: []string{"02:11:22:33:44:55"}, ExcludedMACs: []string{"02:11:22:33:44:66"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return Input{LAN: lan, Revision: 1, Routes: []Route{{
		ServiceID: "network-cell", Resolved: "wireguard:home", Sources: []string{"192.168.1.0/25"},
		Ingress: []string{"br0"}, CIDRs: []string{"8.8.8.0/24"}, NetworkPolicyGeneration: generation, NetworkPolicyRole: "default",
	}}}
}

func TestNetworkPolicyManagerFrozenLANPropagation(t *testing.T) {
	input := networkPolicyLANFixture(t)
	plan, err := BuildAt(input, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	input.LAN.Ingress[0].IncludedMACs[0] = "02:AA:AA:AA:AA:AA"
	input.Routes[0].Sources[0] = "192.168.2.0/24"
	if _, err := plan.FrozenLAN(); err != nil || plan.Routes[0].Sources[0] != "192.168.1.0/25" {
		t.Fatalf("input aliased frozen plan: %v", err)
	}
	scoped := plan.RoutePlanFor("wireguard")
	frozen, err := scoped.FrozenLAN()
	if err != nil || frozen.Generation != plan.LAN.Generation {
		t.Fatalf("scoped LAN: %v", err)
	}
	frozen.Ingress[0].IncludedMACs[0] = "02:BB:BB:BB:BB:BB"
	scoped.LAN.Ingress[0].ExcludedMACs[0] = "02:CC:CC:CC:CC:CC"
	scoped.Routes[0].Ingress[0] = "br1"
	if _, err := plan.FrozenLAN(); err != nil || plan.Routes[0].Ingress[0] != "br0" {
		t.Fatalf("canary aliased full plan: %v", err)
	}
}

func TestNetworkPolicyManagerLANIdentity(t *testing.T) {
	input := networkPolicyLANFixture(t)
	before, err := BuildAt(input, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	gate := input.LAN.Ingress[0]
	gate.ExcludedMACs = []string{"02:11:22:33:44:77"}
	input.LAN, err = CompileLANPolicyRuntime(input.LAN.Generation, []LANPolicyIngress{gate})
	if err != nil {
		t.Fatal(err)
	}
	after, err := BuildAt(input, time.Unix(100, 0))
	if err != nil || before.Digest == after.Digest {
		t.Fatalf("negative boundary missing from plan identity: %v", err)
	}
}

func TestNetworkPolicyManagerLANRejectsUnboundCells(t *testing.T) {
	cases := map[string]func(*Input){
		"generation":      func(i *Input) { i.Routes[0].NetworkPolicyGeneration = strings.Repeat("b", 64) },
		"legacy cell":     func(i *Input) { i.Routes[0].NetworkPolicyGeneration, i.Routes[0].NetworkPolicyRole = "", "" },
		"unknown ingress": func(i *Input) { i.Routes[0].Ingress = []string{"br1"} },
		"outside source":  func(i *Input) { i.Routes[0].Sources = []string{"192.168.2.0/24"} },
		"broader source":  func(i *Input) { i.Routes[0].Sources = []string{"192.168.0.0/16"} },
		"cross family":    func(i *Input) { i.Routes[0].Sources = []string{"fd01::/64"} },
		"tampered seal":   func(i *Input) { i.LAN.Ingress[0].IncludedMACs[0] = "02:11:22:33:44:77" },
		"cartesian source": func(i *Input) {
			second := LANPolicyIngress{SegmentID: "guest", Interface: "br1", Sources: []string{"192.168.2.0/24"}, Membership: "all"}
			i.LAN, _ = CompileLANPolicyRuntime(i.LAN.Generation, append(i.LAN.Ingress, second))
			i.Routes[0].Ingress = []string{"br0", "br1"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := networkPolicyLANFixture(t)
			mutate(&input)
			if _, err := BuildAt(input, time.Unix(100, 0)); err == nil {
				t.Fatal("unbound LAN cell accepted")
			}
		})
	}
}

func TestNetworkPolicyManagerLANMissingPayloadIsNotAuthority(t *testing.T) {
	input := networkPolicyLANFixture(t)
	input.LAN = nil
	// Build remains a legacy-compatible shape preview. Runtime adapters must
	// require the accessor, which cannot grant permission from scalar metadata.
	plan, err := BuildAt(input, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plan.FrozenLAN(); err == nil {
		t.Fatal("missing full LAN accepted")
	}
	if _, err := plan.RoutePlanFor("wireguard").FrozenLAN(); err == nil {
		t.Fatal("missing scoped LAN accepted")
	}
}
