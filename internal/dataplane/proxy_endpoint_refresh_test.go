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

// An endpoint DNS change does not change any LAN forwarding grant. Rebuilding
// all of those grants first can consume the refresh deadline before the RPDB
// addition even starts, leaving a pending generation and the service offline.
func TestProxyEndpointRefreshPreservesAcknowledgedForwarding(t *testing.T) {
	a, processes, old := networkCleanupProxy(t)
	processes.running["sing-box-engine"], processes.running["sing-box-tun"] = true, true
	if err := os.WriteFile(a.engineConfigPath(), []byte(`{"outbounds":[{"type":"vless","server":"node.example","server_port":443}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	leaseBefore, err := os.ReadFile(a.forwardingPath())
	if err != nil {
		t.Fatal(err)
	}
	prior, exists, err := a.readPolicyBinding(old)
	if err != nil || !exists {
		t.Fatal("fixture missing committed receipt", err)
	}
	base := a.Runner
	firewallMutations := 0
	a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "iptables" || name == "ip6tables" {
			if len(args) < 3 || args[2] != "-S" {
				firewallMutations++
				return nil, errors.New("unchanged forwarding must retain its exact acknowledged lease")
			}
		}
		return base.Run(ctx, name, args...)
	})
	plan := Plan{Routes: []Route{{Resolved: "sing-box", Sources: []string{"192.168.1.25/32"}, CIDRs: append([]string(nil), old.Prefixes...)}}}
	if changed, err := a.RefreshPolicy(context.Background(), plan); !changed || err != nil {
		t.Fatal("endpoint-only refresh rebuilt unchanged firewall grants", changed, err)
	}
	current, exists, err := a.loadPolicy()
	if err != nil || !exists || !reflect.DeepEqual(current.Exclusions, []string{"203.0.113.9/32"}) || !reflect.DeepEqual(current.Forwarding, old.Forwarding) || firewallMutations != 0 {
		t.Fatal("endpoint refresh changed LAN grants or lost its endpoint exclusion", err, firewallMutations)
	}
	leaseAfter, err := os.ReadFile(a.forwardingPath())
	if err != nil || string(leaseAfter) != string(leaseBefore) {
		t.Fatal("endpoint refresh replaced forwarding ownership", err)
	}
	binding, exists, err := a.readPolicyBinding(current)
	if err != nil || !exists || binding.Phase != "active" || binding.Generation == prior.Generation {
		t.Fatal("endpoint refresh did not acquire a fresh acknowledged RPDB generation", err)
	}
	if err := a.verifyCommittedReceipt(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if err := a.verifyForwarding(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	root, _ := a.policyGenerationRoot(prior.Generation)
	status, err := a.additionStatus(context.Background(), old, root)
	if err != nil || !status.Removed {
		t.Fatal("endpoint refresh retained the old RPDB generation", err)
	}
	// This optimization never grants a cleanup fallback for an unknown receipt.
	if err := os.WriteFile(a.policyBindingPath(), []byte(strings.Repeat(" ", 8)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RefreshPolicy(context.Background(), plan); !errors.Is(err, ErrProxyPolicyUnknown) || firewallMutations != 0 {
		t.Fatal("unknown receipt admitted another refresh", err)
	}
}

func TestProxyEndpointRefreshRefusesChangedOrUnknownForwardingBeforeMutation(t *testing.T) {
	for _, scenario := range []string{"foreign-rule", "missing-lease", "unknown-receipt", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			a, _, old := networkCleanupProxy(t)
			if err := os.WriteFile(a.engineConfigPath(), []byte(`{"server":"node.example"}`), 0600); err != nil {
				t.Fatal(err)
			}
			runner := a.Runner.(*proxyFakeRunner)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "foreign-rule":
				table := runner.firewall.table("iptables", "filter")
				table[old.Forwarding.Chain] = append(table[old.Forwarding.Chain], []string{"-j", "DROP"})
			case "missing-lease":
				if err := os.Remove(a.forwardingPath()); err != nil {
					t.Fatal(err)
				}
			case "unknown-receipt":
				binding, _, err := a.readPolicyBinding(old)
				if err != nil {
					t.Fatal(err)
				}
				root, _ := a.policyGenerationRoot(binding.Generation)
				if err := os.Remove(filepath.Join(root, policyAdditionFile)); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				cancel()
			}
			mutated := false
			a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if len(receiptMutationCalls([]string{name + " " + strings.Join(args, " ")})) != 0 || (name == "iptables" || name == "ip6tables") && (len(args) < 3 || args[2] != "-S") {
					mutated = true
				}
				return runner.Run(ctx, name, args...)
			})
			bindingBefore, _ := os.ReadFile(a.policyBindingPath())
			policyBefore, _ := os.ReadFile(a.policyPath())
			plan := Plan{Routes: []Route{{Resolved: "sing-box", Sources: []string{"192.168.1.25/32"}, CIDRs: old.Prefixes}}}
			if changed, err := a.RefreshPolicy(ctx, plan); changed || err == nil || mutated {
				t.Fatal("endpoint refresh bypassed the original receipt/lease/cancellation fence", changed, err, mutated)
			}
			bindingAfter, _ := os.ReadFile(a.policyBindingPath())
			policyAfter, _ := os.ReadFile(a.policyPath())
			if string(bindingBefore) != string(bindingAfter) || string(policyBefore) != string(policyAfter) {
				t.Fatal("refused endpoint refresh changed the original policy identity")
			}
		})
	}
}

func TestProxyEndpointRefreshCancellationKeepsUnknownAddOrRestoresKnownAdd(t *testing.T) {
	for _, scenario := range []string{"during-add", "after-acknowledged-add"} {
		t.Run(scenario, func(t *testing.T) {
			a, processes, old := networkCleanupProxy(t)
			processes.running["sing-box-engine"], processes.running["sing-box-tun"] = true, true
			if err := os.WriteFile(a.engineConfigPath(), []byte(`{"server":"node.example"}`), 0600); err != nil {
				t.Fatal(err)
			}
			leaseBefore, _ := os.ReadFile(a.forwardingPath())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			base, canceled := a.Runner, false
			a.Runner = networkCleanupRunner(func(runCtx context.Context, name string, args ...string) ([]byte, error) {
				if err := runCtx.Err(); err != nil {
					return nil, err
				}
				out, err := base.Run(runCtx, name, args...)
				if scenario == "during-add" && !canceled && err == nil && name == "ip" && strings.Contains(strings.Join(args, " "), "rule add") {
					canceled = true
					cancel()
					return out, context.Canceled
				}
				return out, err
			})
			if scenario == "after-acknowledged-add" {
				a.SOCKSProbe = func(context.Context, string) error { canceled = true; cancel(); return context.Canceled }
			}
			plan := Plan{Routes: []Route{{Resolved: "sing-box", Sources: []string{"192.168.1.25/32"}, CIDRs: old.Prefixes}}}
			if changed, err := a.RefreshPolicy(ctx, plan); changed || !errors.Is(err, context.Canceled) || !canceled {
				t.Fatal("endpoint refresh lost cancellation", changed, err)
			}
			leaseAfter, _ := os.ReadFile(a.forwardingPath())
			if string(leaseBefore) != string(leaseAfter) || len(processes.running) != 2 {
				t.Fatal("cancellation changed the original firewall lease or runtime")
			}
			if scenario == "during-add" {
				if _, _, err := a.readPolicyBinding(old); !errors.Is(err, ErrProxyPolicyUnknown) {
					t.Fatal("unknown new addition revived historical policy authority", err)
				}
				if _, err := a.RefreshPolicy(context.Background(), plan); !errors.Is(err, ErrProxyPolicyUnknown) {
					t.Fatal("unknown new addition replayed refresh", err)
				}
				if err := a.Deactivate(context.Background()); !errors.Is(err, ErrProxyPolicyUnknown) {
					t.Fatal("unknown new addition admitted destructive cleanup", err)
				}
			} else {
				current, _, err := a.loadPolicy()
				if err != nil || proxyPolicyDigest(current) != proxyPolicyDigest(old) {
					t.Fatal("known canceled refresh did not restore original policy", err)
				}
				if err := a.verifyCommittedReceipt(context.Background(), current); err != nil {
					t.Fatal("restoration lacks a fresh acknowledged generation", err)
				}
			}
		})
	}
}
