package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The public Stage/Refresh producers use the existing stateful RPDB/firewall
// model. Successful command returns still have to create exact receipts.
func proxyNetworkPolicyProducerFixture(t *testing.T, engine, role string) (*ProxyTunnelAdapter, Plan, string, *[]string) {
	t.Helper()
	f := newProxyLANFixture(t)
	a := f.a
	coordinates, err := NewProxyTunnelAdapter(engine, a.Configs, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a.EngineID, a.StateRoot = coordinates.EngineID, coordinates.StateRoot
	a.Interface, a.Table, a.Priority = coordinates.Interface, coordinates.Table, coordinates.Priority
	a.SOCKSPort, a.TunnelCIDR = coordinates.SOCKSPort, coordinates.TunnelCIDR
	a.EngineBin, a.SidecarBin = engine, "sing-box"
	a.bootIdentity = func() (string, error) { return "proxy-network-producer-model-boot", nil }
	a.Processes = &proxyFakeProcesses{running: map[string]bool{}}
	a.SOCKSProbe = func(context.Context, string) error { return nil }
	mutations := []string{}
	base := a.Runner
	a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		if name == "ip" && (strings.Contains(command, "rule add") || strings.Contains(command, "rule del") || strings.Contains(command, "route add") || strings.Contains(command, "route del")) || (name == "iptables" || name == "ip6tables") && !strings.Contains(command, " -S") {
			mutations = append(mutations, name+" "+command)
		}
		if name == "ip" && strings.HasPrefix(command, "link show dev ") {
			return []byte(a.Interface + ": UP"), nil
		}
		return base.Run(ctx, name, args...)
	})
	source := `{"outbounds":[{"type":"vless","server":"203.0.113.9","server_port":443}]}`
	if engine == "xray" {
		source = `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.9","port":443}]}}]}`
	}
	if _, err := a.Configs.Stage(engine, "main", source); err != nil {
		t.Fatal(err)
	}
	destinations := []string{"198.51.100.20/32", "2001:db8::20/128"}
	if role == "default" {
		destinations = []string{"0.0.0.0/0", "::/0"}
	}
	plan := Plan{EngineDrafts: []string{engine + "/main"}, Routes: []Route{{
		ServiceID: "network-cell", Resolved: engine,
		Sources: []string{"192.168.1.0/24", "fd84:db59:da10::/64"}, Ingress: []string{"br0"}, CIDRs: destinations,
		NetworkPolicyGeneration: strings.Repeat("a", 64), NetworkPolicyRole: role,
	}}}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := a.Snapshot(context.Background(), plan, root); err != nil {
		t.Fatal(err)
	}
	return a, plan, root, &mutations
}

func TestProxyStageProducesManagedGenerationBeforeForwarding(t *testing.T) {
	for _, engine := range []string{"sing-box", "xray"} {
		for _, role := range []string{"default", "override"} {
			t.Run(engine+"/"+role, func(t *testing.T) {
				a, plan, root, mutations := proxyNetworkPolicyProducerFixture(t, engine, role)
				if err := a.Stage(context.Background(), plan, root); err != nil {
					t.Fatal("public Stage lost reviewed managed authority", err)
				}
				state, err := a.readStagedPolicy(root)
				if err != nil || state.NetworkPolicyGeneration != plan.Routes[0].NetworkPolicyGeneration || state.NetworkDefault != (role == "default") || state.RuleLayout != 2 || state.SharedPriorityBase == 0 || len(state.Rules) != 2 || state.Forwarding == nil || len(state.Forwarding.Rules) != 2 {
					t.Fatalf("staged policy lost generation, role or layout: %+v %v", state, err)
				}
				for _, rule := range state.Rules {
					if !rule.Managed || rule.Ingress != "br0" {
						t.Fatal("managed classifier binding was lost", rule)
					}
				}
				if len(*mutations) != 0 {
					t.Fatal("Stage changed the modeled kernel", *mutations)
				}
			})
		}
	}
}

func commitProxyNetworkProducerPolicy(t *testing.T, a *ProxyTunnelAdapter, plan Plan, root string) PolicyState {
	t.Helper()
	if err := a.Stage(context.Background(), plan, root); err != nil {
		t.Fatal(err)
	}
	state, err := a.readStagedPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(a.runtimeRoot(), 0o700); err != nil {
		t.Fatal(err)
	}
	for source, destination := range map[string]string{
		"engine.staged.json": a.engineConfigPath(), "sidecar.staged.json": a.sidecarConfigPath(),
	} {
		data, err := os.ReadFile(filepath.Join(root, source))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.applyRetainedPolicy(context.Background(), state); err != nil {
		t.Fatal("model failed to acquire exact acknowledged committed policy", err)
	}
	p := a.Processes.(*proxyFakeProcesses)
	p.running[a.engineProcess().ID], p.running[a.sidecarProcess().ID] = true, true
	return state
}

func TestProxyRefreshPreservesManagedGenerationAndRecordedLayout(t *testing.T) {
	for _, role := range []string{"default", "override"} {
		t.Run(role, func(t *testing.T) {
			a, plan, root, mutations := proxyNetworkPolicyProducerFixture(t, "sing-box", role)
			old := commitProxyNetworkProducerPolicy(t, a, plan, root)
			*mutations = nil
			if changed, err := a.RefreshPolicy(context.Background(), plan); changed || err != nil || len(*mutations) != 0 {
				t.Fatal("identical managed refresh should only verify receipts", changed, err, *mutations)
			}
			plan.Routes[0].Sources = []string{"192.168.1.128/25", "fd84:db59:da10::/80"}
			if changed, err := a.RefreshPolicy(context.Background(), plan); !changed || err != nil {
				t.Fatal("managed source refresh failed", changed, err)
			}
			current, exists, err := a.loadPolicy()
			if err != nil || !exists || current.NetworkPolicyGeneration != old.NetworkPolicyGeneration || current.NetworkDefault != old.NetworkDefault || current.RuleLayout != old.RuleLayout || current.SharedPriorityBase != old.SharedPriorityBase || reflect.DeepEqual(current.Rules, old.Rules) {
				t.Fatalf("refresh lost managed authority or recorded coordinates: %+v %v", current, err)
			}
			if err := a.verifyCommittedReceipt(context.Background(), current); err != nil {
				t.Fatal("refresh lacks actual modeled addition acknowledgements", err)
			}
			if err := a.verifyForwarding(context.Background(), current); err != nil {
				t.Fatal("refresh lost exact forwarding grants", err)
			}
		})
	}
}

func TestProxyRefreshRefusesAuthorityMigrationBeforeEffects(t *testing.T) {
	for _, change := range []string{"generation", "role", "legacy", "malformed"} {
		t.Run(change, func(t *testing.T) {
			a, plan, root, mutations := proxyNetworkPolicyProducerFixture(t, "sing-box", "override")
			old := commitProxyNetworkProducerPolicy(t, a, plan, root)
			before := map[string][]byte{}
			for _, path := range []string{a.policyPath(), a.policyBindingPath(), a.forwardingPath()} {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				before[path] = data
			}
			switch change {
			case "generation":
				plan.Routes[0].NetworkPolicyGeneration = strings.Repeat("b", 64)
			case "role":
				plan.Routes[0].NetworkPolicyRole = "default"
			case "legacy":
				plan.Routes[0].NetworkPolicyGeneration, plan.Routes[0].NetworkPolicyRole = "", ""
			case "malformed":
				plan.Routes[0].NetworkPolicyGeneration = "unreviewed"
			}
			*mutations = nil
			if changed, err := a.RefreshPolicy(context.Background(), plan); changed || !errors.Is(err, ErrNetworkPolicyAuthority) || len(*mutations) != 0 {
				t.Fatal("refresh migrated managed authority or mutated before refusal", changed, err, *mutations)
			}
			for path, data := range before {
				after, err := os.ReadFile(path)
				if err != nil || !reflect.DeepEqual(data, after) {
					t.Fatal("refusal changed recorded policy or ownership", path, err)
				}
			}
			if err := a.verifyCommittedReceipt(context.Background(), old); err != nil {
				t.Fatal("refusal consumed the old receipt", err)
			}
		})
	}
}

func TestProxyRefreshPreservesLegacyCoordinatesAndRefusesManagedMigration(t *testing.T) {
	a, processes, old := networkCleanupProxy(t)
	processes.running[a.engineProcess().ID], processes.running[a.sidecarProcess().ID] = true, true
	plan := Plan{Routes: []Route{{Resolved: "sing-box", Sources: []string{"192.168.1.25/32"}, CIDRs: []string{"198.51.100.21/32"}}}}
	if changed, err := a.RefreshPolicy(context.Background(), plan); !changed || err != nil {
		t.Fatal("legacy refresh failed", changed, err)
	}
	current, exists, err := a.loadPolicy()
	if err != nil || !exists || current.RuleLayout != old.RuleLayout || current.SharedPriorityBase != old.SharedPriorityBase || current.NetworkPolicyGeneration != "" || current.NetworkDefault {
		t.Fatalf("legacy refresh changed recorded coordinates: %+v %v", current, err)
	}
	base, calls := a.Runner, 0
	a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls++
		return base.Run(ctx, name, args...)
	})
	plan.Routes[0].NetworkPolicyGeneration, plan.Routes[0].NetworkPolicyRole = strings.Repeat("a", 64), "override"
	plan.Routes[0].Ingress = []string{"br0"}
	if changed, err := a.RefreshPolicy(context.Background(), plan); changed || !errors.Is(err, ErrNetworkPolicyAuthority) || calls != 0 {
		t.Fatal("legacy refresh accepted managed authority without new Apply", changed, err, calls)
	}
	if err := a.verifyCommittedReceipt(context.Background(), current); err != nil {
		t.Fatal("refused migration consumed legacy receipt", err)
	}
}
