package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func committedWGNetworkEffectFixture(t *testing.T) (*WARPWireGuardAdapter, *warpFakeRunner, Plan, context.Context, warpWGPolicyReference, wgNetworkEffects, *proxyFirewallFake) {
	t.Helper()
	a, kernel, plan, root, ctx := wgNetworkLifecycleFixture(t, true)
	for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Activate, a.Commit} {
		if err := step(ctx, plan, root); err != nil {
			t.Fatal(err)
		}
	}
	state, exists, err := a.loadPolicyState()
	if err != nil || !exists {
		t.Fatal("missing committed network intent", err)
	}
	ref, err := a.committedWGPolicyReference(state)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := a.compileWGNetworkEffects(ref)
	if err != nil {
		t.Fatal(err)
	}
	return a, kernel, plan, ctx, ref, compiled, a.Runner.(wgNetworkLANReadbackRunner).firewall
}

func TestWGNetworkMixedReceiptBindsOwnSourceNATAndPreservesFirmwareACL(t *testing.T) {
	a, kernel, _, ctx, ref, compiled, firewall := committedWGNetworkEffectFixture(t)
	data, err := os.ReadFile(filepath.Join(a.wgPolicyGenerationRoot(ref, ""), policyAdditionFile))
	if err != nil {
		t.Fatal(err)
	}
	var receipt policyAdditionDocument
	if err := json.Unmarshal(data, &receipt); err != nil || receipt.Schema != 2 || len(receipt.Steps) != len(compiled.plan.Effects) {
		t.Fatal("routing/firewall did not use one mixed receipt", receipt.Schema, err)
	}
	for _, table := range compiled.tables {
		name, own := "iptables", "10.66.0.2"
		if table.v6 {
			name, own = "ip6tables", "fd66::2"
		}
		chains := firewall.table(name, table.table)
		if table.table == "nat" {
			if len(chains[table.chain]) != 1 || !strings.Contains(strings.Join(chains[table.chain][0], " "), "-j SNAT --to-source "+own) || chains[table.parent][0][len(chains[table.parent][0])-1] != table.chain {
				t.Fatal("own-family SNAT is absent or shadowed by firmware NAT", table, chains)
			}
		} else if strings.Join(chains[table.parent][0], " ") != "-j NDM" {
			t.Fatal("existing firmware ACL priority changed", chains)
		}
	}
	if err := a.Deactivate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, table := range compiled.tables {
		name := "iptables"
		if table.v6 {
			name = "ip6tables"
		}
		chains := firewall.table(name, table.table)
		if _, exists := chains[table.chain]; exists || len(chains[table.parent]) != 1 || strings.Join(chains[table.parent][0], " ") != "-j NDM" || len(chains["NDM"]) != 1 {
			t.Fatal("owned cleanup changed firmware rules or kept its chain", chains)
		}
	}
	if kernel.active || len(kernel.policy.entries) != 0 || len(kernel.policy.defaults) != 0 {
		t.Fatal("mixed cleanup retained owned routing")
	}
}

func TestWGNetworkMixedReceiptCleanupCutsRetainSNATAndRouting(t *testing.T) {
	for _, point := range []string{"cleanup-intent", "delete", "removed"} {
		t.Run(point, func(t *testing.T) {
			a, kernel, _, ctx, ref, compiled, firewall := committedWGNetworkEffectFixture(t)
			last := len(compiled.plan.Effects) - 1
			injected := false
			a.policyReceiptOptions.fault = func(where string, index int) error {
				if where == point && index == last {
					injected = true
					return errors.New("cut during filter attachment removal")
				}
				return nil
			}
			if err := a.Deactivate(ctx); err == nil || !injected {
				t.Fatal("cleanup cut not reached", point, err)
			}
			if !kernel.active || len(kernel.policy.defaults) != 2 || len(kernel.policy.entries) != 2 || !regularFile(a.statePath()) || !regularFile(filepath.Join(a.StateRoot, wgPolicyReferenceFile)) {
				t.Fatal("filter cut removed routing or retained authority", kernel.policy)
			}
			for _, table := range compiled.tables {
				if table.table != "nat" {
					continue
				}
				name := "iptables"
				if table.v6 {
					name = "ip6tables"
				}
				chains := firewall.table(name, table.table)
				if len(chains[table.chain]) != 1 || len(chains[table.parent]) != 2 {
					t.Fatal("cleanup crossed an unsettled filter prerequisite", chains)
				}
			}
			a.policyReceiptOptions.fault = nil
			if point != "removed" {
				beforeIP, beforeFW := len(kernel.calls), len(firewall.calls)
				if err := a.Deactivate(ctx); !errors.Is(err, ErrPolicyAdditionUnknown) {
					t.Fatal("unconfirmed removal was retried from kernel coincidence", err)
				}
				for _, call := range append(append([]string(nil), kernel.calls[beforeIP:]...), firewall.calls[beforeFW:]...) {
					if strings.Contains(call, " del ") || strings.Contains(call, " delete ") || strings.Contains(call, " -D ") || strings.Contains(call, " -X ") {
						t.Fatal("unknown removal admitted another cleanup command", call)
					}
				}
				return
			}
			if err := a.Deactivate(ctx); err != nil {
				t.Fatal("exact retained cleanup retry failed", err)
			}
			status, err := a.inspectWGPolicyReference(ctx, ref, "")
			if err != nil || !status.Removed || status.Unknown || kernel.active || len(kernel.policy.defaults) != 0 {
				t.Fatal("retry did not finish the original receipt", status, err)
			}
		})
	}
}

func TestWGNetworkMixedReceiptUnknownFirewallRowsFenceAllCleanup(t *testing.T) {
	for _, cut := range []string{"duplicate-attachment", "foreign-body", "foreign-reference"} {
		t.Run(cut, func(t *testing.T) {
			a, kernel, _, ctx, _, compiled, firewall := committedWGNetworkEffectFixture(t)
			table := compiled.tables[0]
			chains := firewall.table("iptables", table.table)
			switch cut {
			case "duplicate-attachment":
				chains[table.parent] = append(chains[table.parent], append([]string(nil), table.jumps[0]...))
			case "foreign-body":
				chains[table.chain] = append(chains[table.chain], []string{"-j", "DROP"})
			default:
				chains["NDM"] = append(chains["NDM"], []string{"-j", table.chain})
			}
			beforeIP, beforeFW := len(kernel.calls), len(firewall.calls)
			if err := a.Deactivate(ctx); err == nil {
				t.Fatal("unknown firewall authority was adopted", cut)
			}
			for _, call := range append(append([]string(nil), kernel.calls[beforeIP:]...), firewall.calls[beforeFW:]...) {
				if strings.Contains(call, " del ") || strings.Contains(call, " delete ") || strings.Contains(call, " -D ") || strings.Contains(call, " -X ") {
					t.Fatal("unknown firewall row allowed a cleanup command", call)
				}
			}
			if !kernel.active || len(kernel.policy.entries) != 2 || len(kernel.policy.defaults) != 2 || !regularFile(a.statePath()) {
				t.Fatal("unknown namespace lost retained owner state")
			}
		})
	}
}

func TestWGNetworkWholeServiceTableRefusesSpecificRoutesAndWrongDefaultTuple(t *testing.T) {
	for _, phase := range []string{"stage", "health"} {
		for _, cut := range []string{"specific4", "specific6", "metric", "gateway", "protocol"} {
			t.Run(phase+"/"+cut, func(t *testing.T) {
				a, kernel, plan, root, ctx := wgNetworkLifecycleFixture(t, true)
				if err := a.Snapshot(ctx, plan, root); err != nil {
					t.Fatal(err)
				}
				if phase == "health" {
					for _, step := range []func(context.Context, Plan, string) error{a.Stage, a.Activate} {
						if err := step(ctx, plan, root); err != nil {
							t.Fatal(err)
						}
					}
				}
				if cut == "specific4" || cut == "specific6" {
					key, destination := "4|198.51.100.20/32", "198.51.100.20/32"
					if cut == "specific6" {
						key, destination = "6|2001:db8::20/128", "2001:db8::20/128"
					}
					if kernel.endpoint.routes == nil {
						kernel.endpoint.routes = map[string]wgEndpointRoute{}
					}
					kernel.endpoint.routes[key] = wgEndpointRoute{Destination: destination, Device: "foreign", Table: json.RawMessage("206")}
				} else {
					base := a.Runner
					a.Runner = networkCleanupRunner(func(c context.Context, name string, args ...string) ([]byte, error) {
						if name == "ip" && strings.Join(args, " ") == "-N -j route show table 206" {
							row := map[string]any{"dst": "default", "dev": "rz-wg", "protocol": 3, "scope": 253, "metric": 0}
							switch cut {
							case "metric":
								row["metric"] = 99
							case "gateway":
								row["gateway"] = "93.184.216.1"
							case "protocol":
								row["protocol"] = 4
							}
							return json.Marshal([]map[string]any{row})
						}
						return base.Run(c, name, args...)
					})
				}
				before := len(kernel.calls)
				var err error
				if phase == "stage" {
					err = a.Stage(ctx, plan, root)
				} else {
					err = a.Health(ctx, plan, root)
				}
				if err == nil {
					t.Fatal("full CIDR relied on a sampled default while foreign table rows existed")
				}
				for _, call := range kernel.calls[before:] {
					if strings.Contains(call, " add ") || strings.Contains(call, " del ") || strings.Contains(call, " delete ") {
						t.Fatal("read-only whole-table refusal mutated routing", call)
					}
				}
			})
		}
	}
}

func TestWGNetworkBackgroundWorkCannotReplaceFrozenLANScope(t *testing.T) {
	for _, phase := range []string{"reconcile", "refresh"} {
		for _, change := range []string{"generation", "membership"} {
			t.Run(phase+"/"+change, func(t *testing.T) {
				a, kernel, plan, ctx, ref, _, firewall := committedWGNetworkEffectFixture(t)
				if err := a.verifyWGNetworkReferenceScope(plan, ref); err != nil {
					t.Fatal("original complete scope refused", err)
				}
				if change == "generation" {
					plan.Routes[0].NetworkPolicyGeneration = strings.Repeat("b", 64)
				} else {
					plan.LAN.Ingress[0].Membership = "mac"
					plan.LAN.Ingress[0].IncludedMACs = []string{"02:00:00:00:00:01"}
				}
				var err error
				plan.LAN, err = CompileLANPolicyRuntime(plan.Routes[0].NetworkPolicyGeneration, plan.LAN.Ingress)
				if err != nil {
					t.Fatal(err)
				}
				beforeIP, beforeFW := len(kernel.calls), len(firewall.calls)
				if phase == "reconcile" {
					err = a.Reconcile(ctx, plan)
				} else {
					_, err = a.RefreshPolicy(ctx, plan)
				}
				if !errors.Is(err, ErrWGNetworkPolicy) {
					t.Fatal("background path replaced the whole frozen classifier", err)
				}
				for _, call := range append(append([]string(nil), kernel.calls[beforeIP:]...), firewall.calls[beforeFW:]...) {
					if strings.Contains(call, " add ") || strings.Contains(call, " del ") || strings.Contains(call, " delete ") || strings.Contains(call, " -A ") || strings.Contains(call, " -D ") || strings.Contains(call, " -X ") {
						t.Fatal("changed scope triggered background mutation", call)
					}
				}
			})
		}
	}
}

func TestAWGNetworkCompilerUsesItsOwnNamespaceAndSameMixedReceiptContract(t *testing.T) {
	wg, _, _, _, ref, _, _ := committedWGNetworkEffectFixture(t)
	awg := NewAmneziaWGAdapter(nil, t.TempDir())
	state := cloneWGPolicyState(ref.Policy)
	state.Interface, state.Table, state.PriorityBase = awg.interfaceName(), awg.table(), awg.priorityBase()
	state.RuleLayout, state.SharedPriorityBase = 0, 0
	initializePolicyLayout(&state)
	state.Forwarding.Chain = awg.wgForwardingObserver().forwardingChain()
	spec, err := awg.endpointSpec()
	if err != nil {
		t.Fatal(err)
	}
	state.WireGuardEndpoint.Table, state.WireGuardEndpoint.Priority, state.WireGuardEndpoint.Mark = spec.EndpointTable, spec.EndpointPriority, spec.EndpointMark
	ref.Policy, ref.ID, ref.Checksum = state, "", ""
	compiled, err := awg.compileWGNetworkEffects(ref)
	if err != nil {
		t.Fatal("AWG did not compile the complete same source scope", err)
	}
	if state.Table != 205 || state.WireGuardEndpoint.Table != 212 || state.Forwarding.Chain == wg.wgForwardingObserver().forwardingChain() {
		t.Fatal("AWG adopted WG coordinates or namespace")
	}
	for _, table := range compiled.tables {
		if table.table == "nat" && !strings.Contains(strings.Join(table.rules[0], " "), "-j SNAT --to-source ") {
			t.Fatal("AWG used proxy NAT exemption instead of its own source NAT")
		}
	}
	if _, err := PolicyEffectPlanDigest(compiled.plan); err != nil {
		t.Fatal("AWG bypassed the common bounded DAG", err)
	}
}
