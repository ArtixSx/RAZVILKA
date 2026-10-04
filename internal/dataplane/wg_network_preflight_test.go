package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestWGNetworkMixedPreflightRequiresNumericPrecedenceAndEmptyReservedSlots(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, collision := range []string{"earlier-overlap", "equal-slot", "other-reserved-slot", "unknown-earlier"} {
			t.Run(map[int]string{4: "ipv4", 6: "ipv6"}[family]+"/"+collision, func(t *testing.T) {
				a, kernel, plan, root, ctx := wgNetworkLifecycleFixture(t, true)
				for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage} {
					if err := step(ctx, plan, root); err != nil {
						t.Fatal(err)
					}
				}
				state, err := a.readStagedPolicy(root)
				if err != nil {
					t.Fatal(err)
				}
				ref := warpWGPolicyReference{Policy: state, FrozenLAN: plan.LAN, NetworkTunnelSources: []string{"10.66.0.2", "fd66::2"}, NetworkHealthVersion: wgNetworkHealthVersion}
				compiled, err := a.compileWGNetworkEffects(ref)
				if err != nil {
					t.Fatal(err)
				}
				source := "192.168.1.0/24"
				if family == 6 {
					source = "fd01::/64"
				}
				line := "69: from " + source + " iif br0 lookup 214"
				switch collision {
				case "equal-slot":
					line = "71: from all lookup 214"
				case "other-reserved-slot":
					line = "70: from all iif foreign lookup 214"
				case "unknown-earlier":
					line = "69: not from " + source + " iif br0 lookup 214"
				}
				firewall := a.Runner.(wgNetworkLANReadbackRunner).firewall
				base := a.Runner
				read := "-N rule show"
				if family == 6 {
					read = "-N -6 rule show"
				}
				a.Runner = networkCleanupRunner(func(c context.Context, name string, args ...string) ([]byte, error) {
					data, err := base.Run(c, name, args...)
					if name == "ip" && strings.Join(args, " ") == read {
						data = append(data, []byte("\n"+line+"\n")...)
					}
					return data, err
				})
				beforeIP, beforeFW := len(kernel.calls), len(firewall.calls)
				if err := applyPolicyEffects(ctx, a.wgNetworkEffectRuntime(ref, compiled, true), compiled.plan, t.TempDir(), a.policyReceiptOptions); err == nil {
					t.Fatal("tuple absence bypassed precedence or reserved slot collision")
				}
				assertWGNetworkReadOnlyCalls(t, kernel.calls[beforeIP:], firewall.calls[beforeFW:])
				calls := strings.Join(kernel.calls[beforeIP:], "\n")
				if !strings.Contains(calls, "ip -N rule show") || family == 6 && !strings.Contains(calls, "ip -N -6 rule show") {
					t.Fatal("precedence used symbolic readback", calls)
				}
				if len(kernel.policy.entries) != 0 || len(kernel.policy.defaults) != 0 {
					t.Fatal("collision allowed the first mixed routing effect")
				}
			})
		}
	}
}

func assertWGNetworkReadOnlyCalls(t *testing.T, groups ...[]string) {
	t.Helper()
	for _, calls := range groups {
		for _, call := range calls {
			for _, mutation := range []string{" add ", " del ", " delete ", " set ", " setconf ", " -N ", " -A ", " -I ", " -D ", " -X "} {
				if strings.Contains(call, mutation) && !(mutation == " -N " && strings.HasPrefix(call, "ip -N ")) {
					t.Fatal("read-only refusal issued a mutation", call)
				}
			}
		}
	}
}

func TestWGNetworkFreshPhysicalScopeFencesActivateHealthAndRecovery(t *testing.T) {
	for _, phase := range []string{"activate", "health", "reconcile"} {
		for _, drift := range []string{"prefix-shrink4", "prefix-shrink6", "down", "WAN-member", "WAN-interface"} {
			t.Run(phase+"/"+drift, func(t *testing.T) {
				a, kernel, plan, root, ctx := wgNetworkLifecycleFixture(t, true)
				steps := []func(context.Context, Plan, string) error{a.Snapshot, a.Stage}
				if phase != "activate" {
					steps = append(steps, a.Activate)
				}
				if phase == "reconcile" {
					steps = append(steps, a.Commit)
				}
				for _, step := range steps {
					if err := step(ctx, plan, root); err != nil {
						t.Fatal(err)
					}
				}
				base := a.Runner
				if drift == "WAN-member" {
					a.networkLANBridgeMembers = func(context.Context, string) ([]string, error) { return []string{"wan0"}, nil }
				}
				a.Runner = networkCleanupRunner(func(c context.Context, name string, args ...string) ([]byte, error) {
					command := strings.Join(args, " ")
					if drift == "WAN-interface" && name == "ip" && command == "route show table main default" {
						return []byte("default dev br0\n"), nil
					}
					data, err := base.Run(c, name, args...)
					if name == "ip" && (strings.Contains(command, "route show table main") || strings.Contains(command, "addr show dev br0")) {
						switch drift {
						case "prefix-shrink4":
							data = []byte(strings.ReplaceAll(string(data), "/24", "/25"))
						case "prefix-shrink6":
							data = []byte(strings.ReplaceAll(string(data), "/64", "/65"))
						case "down":
							data = []byte(strings.ReplaceAll(string(data), ",UP>", ">"))
						}
					}
					return data, err
				})
				firewall := base.(wgNetworkLANReadbackRunner).firewall
				beforeIP, beforeFW := len(kernel.calls), len(firewall.calls)
				a.HealthProbe = func(context.Context, string) error { t.Fatal("physical drift reached TCP health"); return nil }
				a.networkUDPProbe = func(context.Context, netip.Addr) error { t.Fatal("physical drift reached UDP health"); return nil }
				var err error
				switch phase {
				case "activate":
					err = a.Activate(ctx, plan, root)
				case "health":
					err = a.Health(ctx, plan, root)
				case "reconcile":
					err = a.Reconcile(ctx, plan)
				}
				if !errors.Is(err, ErrWGNetworkPolicy) {
					t.Fatal("frozen forwarding survived physical drift", err)
				}
				assertWGNetworkReadOnlyCalls(t, kernel.calls[beforeIP:], firewall.calls[beforeFW:])
				if phase == "reconcile" && (!kernel.active || !regularFile(a.statePath())) {
					t.Fatal("failed scope proof restarted or removed committed owner")
				}
			})
		}
	}
}
