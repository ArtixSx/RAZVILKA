package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func committedSingBoxLANFixture(t *testing.T, v6 bool) (*proxyLANFixture, Plan, PolicyState) {
	t.Helper()
	f := newProxyLANFixture(t)
	f.a.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
	f.a.NodeRoutes = func(context.Context, []NodeRouteRequest, string, time.Time) (NodeRouteMaterial, error) {
		panic("read-only health must not materialize a node")
	}
	state := f.policy(v6, "")
	if err := f.a.prepareForwarding(context.Background(), &state); err != nil {
		t.Fatal(err)
	}
	route := "sing-box:node-" + strings.Repeat("a", 64)
	plan := Plan{NetworkProfileID: executionNetwork, Routes: []Route{{Selected: route, Resolved: route, CIDRs: append([]string(nil), state.Prefixes...)}}}
	return f, plan, state
}

func TestCommittedSingBoxAllLANRecordedPhysicalScope(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		f, plan, state := committedSingBoxLANFixture(t, v6)
		before, _ := json.Marshal(state)
		if err := f.a.verifyCommittedNodeClientScope(context.Background(), plan, state); err != nil {
			t.Fatalf("recorded sing-box all-LAN physical scope rejected (v6=%v): %v", v6, err)
		}
		after, _ := json.Marshal(state)
		if string(before) != string(after) {
			t.Fatal("read-only scope mutated policy")
		}
	}
}

func TestCommittedSingBoxAllLANRefusesScopeAndAuthorityDrift(t *testing.T) {
	for _, mode := range []string{"wide", "wrong-subnet", "missing-bridge", "wrong-ingress", "wrong-forwarding", "missing-rule", "profile-only", "profile-mixed", "missing-materializer", "wrong-interface", "foreign-destination", "network", "untracked-expansion"} {
		t.Run(mode, func(t *testing.T) {
			f, plan, state := committedSingBoxLANFixture(t, false)
			switch mode {
			case "wide":
				state.Rules[0].Source = "0.0.0.0/0"
			case "wrong-subnet":
				state.Rules[0].Source = "192.168.50.0/24"
			case "missing-bridge":
				f.members = map[string][]string{}
			case "wrong-ingress":
				state.Rules[0].Ingress = "br-wrong"
			case "wrong-forwarding":
				state.Forwarding.Rules[0].Ingress = "eth3"
			case "missing-rule":
				state.Rules = state.Rules[1:]
			case "profile-only":
				plan.Routes[0].Resolved = "sing-box:home"
			case "profile-mixed":
				plan.Routes = append(plan.Routes, Route{Resolved: "sing-box:home", CIDRs: state.Prefixes})
			case "missing-materializer":
				f.a.NodeRoutes = nil
			case "wrong-interface":
				f.a.Interface = "foreign"
			case "foreign-destination":
				state.Rules[0].Destination = "198.51.100.99/32"
			case "network":
				f.a.FreshProfile = func(context.Context) (string, error) { return "wan-aaaaaaaaaaaa", nil }
			case "untracked-expansion":
				state.Rules[0].Source = "" // Empty source must never be treated as recorded physical authority.
			}
			before, _ := json.Marshal(state)
			if err := f.a.verifyCommittedNodeClientScope(context.Background(), plan, state); err == nil {
				t.Fatal("unproved sing-box all-LAN scope accepted", mode)
			}
			after, _ := json.Marshal(state)
			if string(before) != string(after) {
				t.Fatal("refusal mutated policy")
			}
		})
	}
}

func TestCommittedSingBoxAllLANDoesNotBroadenSelectedDestination(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, mode := range []string{"valid", "subnet-for-selected", "wrong-ingress", "foreign-destination", "missing-selected"} {
			t.Run(fmt.Sprintf("v6=%v/%s", v6, mode), func(t *testing.T) {
				f, plan, state := committedSingBoxLANFixture(t, v6)
				destination, selected := "198.51.100.21/32", "192.168.1.25/32"
				if v6 {
					destination, selected = "2001:db8::21/128", "fd84:db59:da10::25/128"
				}
				plan.Routes = append(plan.Routes, Route{Resolved: "sing-box:node-" + strings.Repeat("b", 64), CIDRs: []string{destination}, Sources: []string{selected}})
				prefixes, rules, err := resolvePolicyRules(context.Background(), plan, f.a.ID(), nil)
				if err != nil {
					t.Fatal(err)
				}
				state.Prefixes, state.Rules = prefixes, rules
				if err := f.a.prepareForwarding(context.Background(), &state); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "subnet-for-selected":
					for i := range state.Rules {
						if state.Rules[i].Destination == destination {
							if v6 {
								state.Rules[i].Source = "fd84:db59:da10::/64"
							} else {
								state.Rules[i].Source = "192.168.1.0/24"
							}
						}
					}
				case "wrong-ingress":
					plan.Routes[0].Ingress = []string{"br1"}
				case "foreign-destination":
					state.Prefixes = append(state.Prefixes, "198.51.100.99/32")
				case "missing-selected":
					state.Rules = slices.DeleteFunc(state.Rules, func(r PolicyRule) bool { return r.Destination == destination })
				}
				if mode == "subnet-for-selected" || mode == "missing-selected" {
					state.Forwarding, err = f.a.compileForwarding(context.Background(), state)
					if err != nil {
						t.Fatal(err)
					}
				}
				err = f.a.verifyCommittedNodeClientScope(context.Background(), plan, state)
				if (err == nil) != (mode == "valid") {
					t.Fatalf("mixed tuple scope mode=%s error=%v", mode, err)
				}
			})
		}
	}
}

func TestCommittedSingBoxAllLANNewBridgeIsNotAddedDuringHealth(t *testing.T) {
	f, plan, state := committedSingBoxLANFixture(t, false)
	before, _ := json.Marshal(state)
	f.main4 += "192.168.50.0/24 dev br2 scope link src 192.168.50.1\n"
	f.addresses["br2"] = "37: br2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n inet 192.168.50.1/24 scope global br2\n"
	f.members["br2"] = []string{"guest2"}
	if err := f.a.verifyCommittedNodeClientScope(context.Background(), plan, state); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(state)
	if string(before) != string(after) {
		t.Fatal("new bridge granted by health")
	}
}

func TestCommittedSingBoxAllLANRepeatedFullHealthAndBookends(t *testing.T) {
	for _, mode := range []string{"repeat", "stale-policy", "policy-during", "network-during"} {
		t.Run(mode, func(t *testing.T) {
			f, plan, _ := committedSingBoxLANFixture(t, false)
			a := f.a
			m := New(t.TempDir())
			m.FreshProfile = a.FreshProfile
			plan.SchemaVersion, plan.PlanID, plan.Digest, plan.State, plan.Ready = SchemaVersion, "dp-aaaaaaaaaaaaaaaa", strings.Repeat("a", 64), "committed", true
			plan.Adapters = []string{"sing-box"}
			plan.Routes[0].CIDRs = []string{"8.8.8.8/32"}
			plan.Routes[0].ProbeURL = "https://telegram.org/"
			physical := a.Runner
			processes := &proxyFakeProcesses{running: map[string]bool{}}
			native := &proxyFakeRunner{processes: processes, iface: a.Interface}
			readonly := false
			mutations := 0
			a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if readonly {
					for _, arg := range args {
						if name == "ip" && slices.Contains([]string{"add", "del", "replace"}, arg) || name != "ip" && slices.Contains([]string{"-A", "-N", "-D", "-X"}, arg) {
							mutations++
						}
					}
				}
				plain := args
				if len(plain) > 0 && plain[0] == "-6" {
					plain = plain[1:]
				}
				if name == "ip" && len(plain) > 1 && (strings.HasPrefix(strings.Join(plain, " "), "route show table main") || plain[0] == "addr" || plain[0] == "route" && plain[1] == "get") {
					return physical.Run(ctx, name, args...)
				}
				return native.Run(ctx, name, args...)
			})
			a.Processes = processes
			a.EngineBin, a.SidecarBin = "sing-box", "sing-box"
			a.SOCKSProbe = func(context.Context, string) error { return nil }
			a.Probe = func(context.Context, string) error { return nil }
			a.ServiceIPProbe = func(context.Context, string, string, netip.Addr) error { return nil }
			a.bootIdentity = func() (string, error) { return "singbox-lan-health-boot", nil }
			a.NodeRoutes = func(context.Context, []NodeRouteRequest, string, time.Time) (NodeRouteMaterial, error) {
				return NodeRouteMaterial{Config: []byte(`{"outbounds":[{"type":"vless","server":"node.example","server_port":443}]}`)}, nil
			}
			a.Resolver = func(_ context.Context, host string) ([]netip.Addr, error) {
				if host == "node.example" {
					return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
				}
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			}
			if err := m.Register(a); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(m.StateRoot, "transactions", plan.PlanID, a.ID())
			for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Activate, a.Health, a.Commit} {
				if err := step(context.Background(), plan, root); err != nil {
					t.Fatal("install owned fixture", err)
				}
			}
			if err := m.Record(plan); err != nil {
				t.Fatal(err)
			}
			policyBefore, err := os.ReadFile(a.policyPath())
			if err != nil {
				t.Fatal(err)
			}
			bindingBefore, err := os.ReadFile(a.policyBindingPath())
			if err != nil {
				t.Fatal(err)
			}
			starts := len(processes.startSpecs)
			running := map[string]bool{}
			for k, v := range processes.running {
				running[k] = v
			}
			changePolicy := func() {
				var changed PolicyState
				if json.Unmarshal(policyBefore, &changed) != nil {
					t.Fatal("policy fixture")
				}
				changed.Exclusions = append(changed.Exclusions, "9.9.9.9/32")
				raw, _ := json.Marshal(changed)
				if err := os.WriteFile(a.policyPath(), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			probeCalls := 0
			switch mode {
			case "stale-policy":
				changePolicy()
			case "policy-during":
				a.ServiceIPProbe = func(context.Context, string, string, netip.Addr) error { probeCalls++; changePolicy(); return nil }
			case "network-during":
				a.ServiceIPProbe = func(context.Context, string, string, netip.Addr) error {
					probeCalls++
					a.FreshProfile = func(context.Context) (string, error) { return "wan-ffffffffffff", nil }
					return nil
				}
			}
			readonly = true
			for n := 0; n < 2; n++ {
				err := m.CheckCommittedNodeHealth(context.Background(), plan)
				if (err == nil) != (mode == "repeat") {
					t.Fatalf("health mode=%s error=%v", mode, err)
				}
				if mode == "policy-during" && n == 0 && (!errors.Is(err, ErrReviewChanged) || probeCalls != 1) {
					t.Fatal("closing policy bookend was not reached", err)
				}
				if mode == "network-during" && !errors.Is(err, ErrNetworkChanged) {
					t.Fatal("fresh network guard lost", err)
				}
			}
			if starts != len(processes.startSpecs) || !reflect.DeepEqual(running, processes.running) || mutations != 0 {
				t.Fatal("read-only health started/stopped a process or changed kernel policy")
			}
			bindingAfter, _ := os.ReadFile(a.policyBindingPath())
			if string(bindingBefore) != string(bindingAfter) {
				t.Fatal("health rewrote owned receipt")
			}
			if mode == "repeat" {
				after, _ := os.ReadFile(a.policyPath())
				if string(policyBefore) != string(after) {
					t.Fatal("repeat health rewrote policy")
				}
			}
		})
	}
}
