package dataplane

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestCommittedXrayAllLANScopeUsesOnlyRecordedPhysicalPrefixes(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		f := newProxyLANFixture(t)
		a := f.a
		a.EngineID = "xray"
		a.scopedXray = true
		a.nodeRouterVerifier = true
		a.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
		state := f.policy(v6, "")
		if err := a.prepareForwarding(context.Background(), &state); err != nil {
			t.Fatal(err)
		}
		plan := Plan{NetworkProfileID: executionNetwork, Routes: []Route{{Resolved: "xray:node-" + strings.Repeat("a", 64), CIDRs: append([]string(nil), state.Prefixes...)}}}
		before, _ := json.Marshal(state)
		// Another bridge can appear, but health must neither add it nor require a
		// fresh wider all-LAN expansion instead of the original recorded scope.
		if !v6 {
			f.main4 += "192.168.50.0/24 dev br2 scope link src 192.168.50.1\n"
			f.addresses["br2"] = "37: br2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n inet 192.168.50.1/24 scope global br2\n"
			f.members["br2"] = []string{"guest2"}
			plan.Routes = append(plan.Routes, Route{Resolved: plan.Routes[0].Resolved, CIDRs: append([]string(nil), state.Prefixes...), Sources: []string{"192.168.1.25/32"}})
		}
		if err := a.verifyCommittedNodeClientScope(context.Background(), plan, state); err != nil {
			t.Fatal("recorded bridge scope rejected", v6, err)
		}
		after, _ := json.Marshal(state)
		if string(before) != string(after) {
			t.Fatal("health widened or rewrote recorded policy")
		}
	}
}

func TestCommittedXrayAllLANScopeRejectsDriftAndUnprovenSources(t *testing.T) {
	for _, mode := range []string{"wide", "unrecorded", "missing-bridge", "wrong-ingress", "wrong-forwarding", "missing-source", "external-only", "selected-only", "network"} {
		t.Run(mode, func(t *testing.T) {
			f := newProxyLANFixture(t)
			a := f.a
			a.EngineID = "xray"
			a.scopedXray = true
			a.nodeRouterVerifier = true
			a.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
			state := f.policy(false, "")
			if err := a.prepareForwarding(context.Background(), &state); err != nil {
				t.Fatal(err)
			}
			plan := Plan{NetworkProfileID: executionNetwork, Routes: []Route{{Resolved: "xray:node-" + strings.Repeat("a", 64), CIDRs: append([]string(nil), state.Prefixes...)}}}
			switch mode {
			case "wide":
				state.Rules[0].Source = "0.0.0.0/0"
			case "unrecorded":
				state.Rules[0].Source = "10.80.0.0/24"
			case "missing-bridge":
				f.members = map[string][]string{}
			case "wrong-ingress":
				state.Rules[0].Ingress = "br-wrong"
			case "wrong-forwarding":
				state.Forwarding.Rules[0].Ingress = "eth3"
			case "missing-source":
				state.Rules = state.Rules[1:]
			case "external-only":
				a.nodeRouterVerifier = false
			case "selected-only":
				plan.Routes[0].Sources = []string{"192.168.1.25/32"}
			case "network":
				a.FreshProfile = func(context.Context) (string, error) { return "wan-aaaaaaaaaaaa", nil }
			}
			before, _ := json.Marshal(state)
			if err := a.verifyCommittedNodeClientScope(context.Background(), plan, state); err == nil {
				t.Fatal("unproven scope accepted", mode)
			}
			after, _ := json.Marshal(state)
			if string(before) != string(after) {
				t.Fatal("refusal mutated policy")
			}
		})
	}
}

func TestCommittedXrayAllLANDoesNotBroadenOtherDestinationOrIngress(t *testing.T) {
	for _, mode := range []string{"valid", "subnet-for-selected", "wrong-ingress", "foreign-destination", "missing-selected"} {
		t.Run(mode, func(t *testing.T) {
			f := newProxyLANFixture(t)
			a := f.a
			a.EngineID = "xray"
			a.scopedXray = true
			a.nodeRouterVerifier = true
			a.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
			const destA = "198.51.100.20/32"
			const destB = "198.51.100.21/32"
			plan := Plan{NetworkProfileID: executionNetwork, Routes: []Route{{Resolved: "xray:node-" + strings.Repeat("a", 64), CIDRs: []string{destA}}, {Resolved: "xray:node-" + strings.Repeat("b", 64), CIDRs: []string{destB}, Sources: []string{"192.168.1.25/32"}}}}
			prefixes, rules, err := resolvePolicyRules(context.Background(), plan, a.ID(), nil)
			if err != nil {
				t.Fatal(err)
			}
			state := f.policy(false, "")
			state.Prefixes = prefixes
			state.Rules = rules
			if err := a.prepareForwarding(context.Background(), &state); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "subnet-for-selected":
				for i := range state.Rules {
					if state.Rules[i].Destination == destB {
						state.Rules[i].Source = "192.168.1.0/24"
					}
				}
			case "wrong-ingress":
				plan.Routes[0].Ingress = []string{"br1"}
			case "foreign-destination":
				state.Prefixes = append(state.Prefixes, "198.51.100.22/32")
			case "missing-selected":
				for i, r := range state.Rules {
					if r.Destination == destB {
						state.Rules = append(state.Rules[:i], state.Rules[i+1:]...)
						break
					}
				}
			}
			// Give the altered model a consistent forwarding reconstruction, so the
			// plan tuple check itself must reject it independently of its old digest.
			if mode == "subnet-for-selected" || mode == "missing-selected" {
				state.Forwarding, err = a.compileForwarding(context.Background(), state)
				if err != nil {
					t.Fatal(err)
				}
			}
			err = a.verifyCommittedNodeClientScope(context.Background(), plan, state)
			if (err == nil) != (mode == "valid") {
				t.Fatal("mixed route scope classification", mode, err)
			}
		})
	}
}
