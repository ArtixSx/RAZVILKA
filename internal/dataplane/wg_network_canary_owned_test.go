package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ownedWGNetworkProbeFixture(t *testing.T) (*WARPWireGuardAdapter, *warpFakeRunner, Plan, string, []byte, context.Context) {
	t.Helper()
	a, r, plan, root := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
	ctx := context.WithValue(context.Background(), reviewGuardKey{}, func(context.Context) error { return nil })
	for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Activate, a.Commit} {
		if err := step(ctx, plan, root); err != nil {
			t.Fatal(err)
		}
	}
	second := filepath.Join(t.TempDir(), "transaction")
	if err := a.Snapshot(ctx, plan, second); err != nil {
		t.Fatal(err)
	}
	profile := mustRead(a.RuntimeConfigPath)
	public, err := wgRuntimePublicKey(profile)
	if err != nil {
		t.Fatal(err)
	}
	peer := "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="
	a.Runner = &wgIdentityRunner{warpFakeRunner: r, identities: []byte(a.interfaceName() + "\t" + public + "\n"), identityTool: "wg", peerReadback: map[string]string{
		"peers": peer + "\n", "endpoints": peer + "\t93.184.216.34:51820\n", "allowed-ips": peer + "\t0.0.0.0/0\n", "preshared-keys": peer + "\t(none)\n",
	}}
	r.routeDevice = a.interfaceName()
	r.calls = nil
	return a, r, plan, second, profile, ctx
}

func TestWGNetworkOwnedCanaryUsesLiveInterfaceWithoutRestart(t *testing.T) {
	a, r, plan, root, profile, ctx := ownedWGNetworkProbeFixture(t)
	runtimeBefore, stateBefore := mustRead(a.RuntimeConfigPath), mustRead(a.statePath())
	starts := r.starts
	tcp, udp := 0, 0
	a.CanaryProbe = func(c context.Context, _ string, source string) error {
		if c.Value(wgSocketInterfaceKey{}) != a.interfaceName() || source != "10.66.0.2" {
			t.Fatal("probe escaped owned runtime", source)
		}
		tcp++
		return nil
	}
	a.networkUDPProbe = func(c context.Context, source netip.Addr) error {
		if c.Value(wgSocketInterfaceKey{}) != a.interfaceName() || source.String() != "10.66.0.2" {
			t.Fatal("UDP escaped owned runtime", source)
		}
		udp++
		return nil
	}
	if err := a.probeOwnedWGNetworkCandidate(ctx, plan.RoutePlanFor(a.ID()), root, profile, []netip.Addr{netip.MustParseAddr("10.66.0.2")}); err != nil {
		t.Fatal(err, tcp, udp, r.calls)
	}
	if tcp != 1 || udp != 1 || r.starts != starts || !r.active || string(mustRead(a.RuntimeConfigPath)) != string(runtimeBefore) || string(mustRead(a.statePath())) != string(stateBefore) {
		t.Fatal("owned probe changed the committed runtime", tcp, udp, r.calls)
	}
	for _, call := range r.calls {
		if strings.Contains(call, " link add ") || strings.Contains(call, " link delete ") || strings.Contains(call, " setconf ") || strings.Contains(call, "wg set ") {
			t.Fatal("owned probe restarted or edited a peer", call)
		}
	}
	if len(r.policy.defaults) != 2 || len(r.policy.entries) != 1 {
		t.Fatal("private health policy was not removed", r.policy)
	}
}

func TestWGNetworkOwnedCanaryRejectsChangedOrUnknownOwnerBeforeMutation(t *testing.T) {
	for _, kind := range []string{"peer", "endpoint", "psk", "runtime", "pending", "boot", "receipt", "fwmark", "foreign-key", "missing-inventory", "missing-review", "live-peer", "live-endpoint", "live-allowed", "live-psk"} {
		t.Run(kind, func(t *testing.T) {
			a, r, plan, root, profile, ctx := ownedWGNetworkProbeFixture(t)
			switch kind {
			case "peer":
				profile = []byte(strings.Replace(string(profile), "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=", 1))
			case "endpoint":
				profile = []byte(strings.Replace(string(profile), "93.184.216.34:51820", "93.184.216.35:443", 1))
			case "psk":
				profile = append(profile, []byte("PresharedKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=\n")...)
			case "runtime":
				if err := os.WriteFile(a.RuntimeConfigPath, append(profile, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "pending":
				if err := os.Mkdir(filepath.Join(a.StateRoot, wgPolicyOperationDirectory), 0700); err != nil {
					t.Fatal(err)
				}
			case "boot":
				a.policyReceiptOptions.boot = func() (string, error) { return "changed-boot", nil }
			case "receipt":
				if err := os.WriteFile(filepath.Join(a.StateRoot, wgPolicyReferenceFile), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "fwmark":
				r.endpoint.mark = "0x0"
			case "foreign-key":
				ri := a.Runner.(*wgIdentityRunner)
				public, _ := wgRuntimePublicKey(profile)
				ri.identities = append(ri.identities, []byte("foreign-wg\t"+public+"\n")...)
			case "missing-inventory":
				a.Runner.(*wgIdentityRunner).identities = nil
			case "missing-review":
				ctx = context.Background()
			case "live-peer":
				a.Runner.(*wgIdentityRunner).peerReadback["peers"] += "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=\n"
			case "live-endpoint":
				ri := a.Runner.(*wgIdentityRunner)
				ri.peerReadback["endpoints"] = strings.Replace(ri.peerReadback["endpoints"], "51820", "443", 1)
			case "live-allowed":
				ri := a.Runner.(*wgIdentityRunner)
				ri.peerReadback["allowed-ips"] = strings.Replace(ri.peerReadback["allowed-ips"], "0.0.0.0/0", "93.184.216.34/32", 1)
			case "live-psk":
				ri := a.Runner.(*wgIdentityRunner)
				ri.peerReadback["preshared-keys"] = strings.Replace(ri.peerReadback["preshared-keys"], "(none)", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=", 1)
			}
			a.CanaryProbe = func(context.Context, string, string) error { t.Fatal("unsafe TCP probe"); return nil }
			a.networkUDPProbe = func(context.Context, netip.Addr) error { t.Fatal("unsafe UDP probe"); return nil }
			if err := a.probeOwnedWGNetworkCandidate(ctx, plan.RoutePlanFor(a.ID()), root, profile, []netip.Addr{netip.MustParseAddr("10.66.0.2")}); err == nil {
				t.Fatal("changed owner admitted")
			}
			assertWGCanaryNoMutations(t, r.calls, root)
		})
	}
}

func TestWGNetworkOwnedCanaryRevocationCleansOnlyHealthSelectors(t *testing.T) {
	a, r, plan, root, profile, ctx := ownedWGNetworkProbeFixture(t)
	revoked := false
	ctx = context.WithValue(ctx, reviewGuardKey{}, func(context.Context) error {
		if revoked {
			return errors.New("scope revoked")
		}
		return nil
	})
	a.CanaryProbe = func(context.Context, string, string) error { return nil }
	a.networkUDPProbe = func(context.Context, netip.Addr) error { revoked = true; return nil }
	if err := a.probeOwnedWGNetworkCandidate(ctx, plan.RoutePlanFor(a.ID()), root, profile, []netip.Addr{netip.MustParseAddr("10.66.0.2")}); err == nil {
		t.Fatal("revoked final scope accepted")
	}
	if !r.active || len(r.policy.defaults) != 2 || len(r.policy.entries) != 1 {
		t.Fatal("revocation did not preserve service/remove health policy", r.calls)
	}
}

func TestWGNetworkOwnedCanaryUnknownRuleDeletionRetainsHealthRoute(t *testing.T) {
	for _, applied := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-syscall", true: "lost-ack"}[applied], func(t *testing.T) {
			a, r, plan, root, profile, ctx := ownedWGNetworkProbeFixture(t)
			base := a.Runner
			failed := false
			a.Runner = networkCleanupRunner(func(c context.Context, name string, args ...string) ([]byte, error) {
				if name == "ip" && strings.HasPrefix(strings.Join(args, " "), "rule del priority 18050 ") {
					failed = true
					if applied {
						if _, err := base.Run(c, name, args...); err != nil {
							t.Fatal(err)
						}
					}
					return nil, errors.New("unknown rule removal")
				}
				if failed && strings.Contains(strings.Join(args, " "), "route del ") {
					t.Fatal("unsettled selector lost its route prerequisite")
				}
				return base.Run(c, name, args...)
			})
			a.CanaryProbe = func(context.Context, string, string) error { return nil }
			a.networkUDPProbe = func(context.Context, netip.Addr) error { return nil }
			if err := a.probeOwnedWGNetworkCandidate(ctx, plan.RoutePlanFor(a.ID()), root, profile, []netip.Addr{netip.MustParseAddr("10.66.0.2")}); !errors.Is(err, ErrPolicyAdditionUnknown) || !failed {
				t.Fatal("unconfirmed selector deletion did not retain authority", err)
			}
			if !r.active || len(r.policy.defaults) != 3 || !regularFile(a.RuntimeConfigPath) || !regularFile(a.statePath()) {
				t.Fatal("unknown health cleanup removed runtime or routing prerequisites", r.calls)
			}
		})
	}
}

func TestWGNetworkCandidateUnknownHealthSelectorKeepsPrivateRuntime(t *testing.T) {
	for _, operation := range []string{"rule add", "rule del", "route del"} {
		t.Run(operation, func(t *testing.T) {
			a, r, plan, root, ctx := wgNetworkLifecycleFixture(t, false)
			readback := a.Runner.(wgNetworkLANReadbackRunner)
			readback.base = &wgIdentityRunner{warpFakeRunner: r, identityTool: "wg", inventory: []byte("[]")}
			a.Runner = readback
			for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage} {
				if err := step(ctx, plan, root); err != nil {
					t.Fatal(err)
				}
			}
			base := a.Runner
			failed := false
			a.Runner = networkCleanupRunner(func(c context.Context, name string, args ...string) ([]byte, error) {
				text := strings.Join(args, " ")
				if name == "ip" && strings.HasPrefix(text, operation+" ") && strings.Contains(text, "219") {
					failed = true
					if _, err := base.Run(c, name, args...); err != nil {
						t.Fatal(err)
					}
					return nil, errors.New("health selector ACK lost")
				}
				if failed && (strings.Contains(text, "link delete") || strings.Contains(text, "route del ")) {
					t.Fatal("unknown health selector allowed prerequisite cleanup", text)
				}
				return base.Run(c, name, args...)
			})
			if err := a.Canary(ctx, plan.RoutePlanFor(a.ID()), root); !errors.Is(err, ErrPolicyAdditionUnknown) || !failed {
				t.Fatal("candidate did not preserve unsettled health authority", err, r.calls)
			}
			if !r.active || !regularFile(filepath.Join(root, "canary", "rz-wg-canary.conf")) {
				t.Fatal("unknown candidate cleanup lost private runtime", r.calls)
			}
		})
	}
}
