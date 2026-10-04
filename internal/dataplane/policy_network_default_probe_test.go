package dataplane

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestManagedDefaultForwardingRequiresExactNetworkScopeInBothFamilies(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprint(v6), func(t *testing.T) {
			f := newProxyLANFixture(t)
			source, destination := "192.168.1.0/24", "0.0.0.0/0"
			if v6 {
				source, destination = "fd84:db59:da10::/64", "::/0"
			}
			state := f.policy(v6, source)
			state.NetworkPolicyGeneration, state.NetworkDefault = strings.Repeat("a", 64), true
			state.Rules[0].Destination, state.Rules[0].Ingress, state.Rules[0].Managed = destination, "br0", true
			state.Prefixes = []string{destination}
			initializePolicyLayout(&state)
			var err error
			state.Forwarding, err = f.a.compileForwarding(context.Background(), state)
			if err != nil {
				t.Fatal("qualified managed default rejected", err)
			}
			if len(state.Forwarding.Rules) != 1 || state.Forwarding.Rules[0].Destination != destination {
				t.Fatal("default grant changed", state.Forwarding)
			}
			for _, change := range []string{"legacy", "override", "unmarked", "missing-ingress", "other-ingress", "global-source", "changed-destination"} {
				bad := state
				bad.Rules = append([]PolicyRule(nil), state.Rules...)
				bad.Forwarding = &ProxyForwardingState{Chain: state.Forwarding.Chain, Rules: append([]ProxyForwardingRule(nil), state.Forwarding.Rules...)}
				switch change {
				case "legacy":
					bad.NetworkPolicyGeneration, bad.NetworkDefault, bad.Rules[0].Managed = "", false, false
				case "override":
					bad.NetworkDefault = false
				case "unmarked":
					bad.Rules[0].Managed = false
				case "missing-ingress":
					bad.Rules[0].Ingress = ""
				case "other-ingress":
					bad.Forwarding.Rules[0].Ingress = "br1"
				case "global-source":
					bad.Rules[0].Source, bad.Forwarding.Rules[0].Source = destination, destination
				case "changed-destination":
					bad.Forwarding.Rules[0].Destination = "203.0.113.20/32"
				}
				if err := f.a.validateForwarding(bad, bad.Forwarding); err == nil {
					t.Fatal("unqualified default accepted", change)
				}
			}
		})
	}
}

func TestManagedSubnetRouteEvidenceSamplesNonLocalSourceWithoutForwardingGrant(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprint(v6), func(t *testing.T) {
			f := newProxyLANFixture(t)
			source, sample := "192.168.1.0/24", "192.168.1.2"
			if v6 {
				source, sample = "fd84:db59:da10::/64", "fd84:db59:da10::2"
			}
			state := f.policy(v6, source)
			state.NetworkPolicyGeneration = strings.Repeat("a", 64)
			state.Rules[0].Ingress, state.Rules[0].Managed = "br0", true
			initializePolicyLayout(&state)
			if err := applyPolicy(context.Background(), f.a.Runner, "ip", state); err != nil {
				t.Fatal("modeled policy installation", err)
			}
			base, forwarded := f.a.Runner, []string{}
			f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				command := strings.Join(args, " ")
				if strings.Contains(command, "route get ") && strings.Contains(command, " from ") {
					forwarded = append(forwarded, command)
				}
				return base.Run(ctx, name, args...)
			})
			if err := verifyPolicyEvidence(context.Background(), f.a.Runner, "ip", state); err != nil {
				t.Fatal(err)
			}
			if len(forwarded) != 1 || !strings.Contains(forwarded[0], " from "+sample+" iif br0 mark 0x20000000") || state.Forwarding != nil {
				t.Fatal("route sample broadened authority", forwarded, state.Forwarding)
			}
			for _, change := range []string{"legacy", "unmarked", "wrong-ingress"} {
				bad := state
				bad.Rules = append([]PolicyRule(nil), state.Rules...)
				switch change {
				case "legacy":
					bad.NetworkPolicyGeneration, bad.Rules[0].Managed = "", false
				case "unmarked":
					bad.Rules[0].Managed = false
				case "wrong-ingress":
					bad.Rules[0].Ingress = "br1"
				}
				if err := verifyPolicyEvidence(context.Background(), f.a.Runner, "ip", bad); err == nil {
					t.Fatal("unproved subnet sample accepted", change)
				}
			}
		})
	}
}

func TestManagedRouteEvidenceDoesNotHideIPv6BehindFourIPv4Samples(t *testing.T) {
	f := newProxyLANFixture(t)
	state := f.policy(false, "192.168.1.0/24")
	state.NetworkPolicyGeneration = strings.Repeat("a", 64)
	state.Rules, state.Prefixes = nil, nil
	for i := 1; i <= 4; i++ {
		destination := fmt.Sprintf("198.51.100.%d/32", i)
		state.Rules = append(state.Rules, PolicyRule{Source: "192.168.1.0/24", Destination: destination, Ingress: "br0", Managed: true})
		state.Prefixes = append(state.Prefixes, destination)
	}
	state.Rules = append(state.Rules, PolicyRule{Source: "fd84:db59:da10::/64", Destination: "2001:db8::20/128", Ingress: "br0", Managed: true})
	state.Prefixes = append(state.Prefixes, "2001:db8::20/128")
	initializePolicyLayout(&state)
	if err := applyPolicy(context.Background(), f.a.Runner, "ip", state); err != nil {
		t.Fatal(err)
	}
	base, checked := f.a.Runner, 0
	f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		if strings.Contains(command, "route get ") && strings.Contains(command, " from ") {
			checked++
			if strings.Contains(command, "route get 2001:db8::20 ") {
				return []byte("2001:db8::20 dev foreign0"), nil
			}
		}
		return base.Run(ctx, name, args...)
	})
	if err := verifyPolicyEvidence(context.Background(), f.a.Runner, "ip", state); err == nil || checked != 5 {
		t.Fatal("managed IPv6 escaped full readback", checked, err)
	}
}

func TestManagedDefaultRouteEvidenceUsesUnicastLiteralAndExactForwardedArguments(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, excludedFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("v6=%t/excluded=%t", v6, excludedFirst), func(t *testing.T) {
				f := newProxyLANFixture(t)
				source, dest, wanted, sample := "192.168.1.0/24", "0.0.0.0/0", "9.9.9.9", "192.168.1.2"
				if v6 {
					source, dest, wanted, sample = "fd84:db59:da10::/64", "::/0", "2620:fe::fe", "fd84:db59:da10::2"
				}
				state := f.policy(v6, source)
				state.NetworkPolicyGeneration, state.NetworkDefault = strings.Repeat("a", 64), true
				state.Prefixes = []string{dest}
				state.Rules[0].Destination, state.Rules[0].Ingress, state.Rules[0].Managed = dest, "br0", true
				if excludedFirst {
					if v6 {
						state.Exclusions, wanted = []string{"2620:fe::/48"}, "2606:4700:4700::1111"
					} else {
						state.Exclusions, wanted = []string{"9.9.9.0/24"}, "1.1.1.1"
					}
				}
				initializePolicyLayout(&state)
				if err := applyPolicy(context.Background(), f.a.Runner, "ip", state); err != nil {
					t.Fatal(err)
				}
				base, calls, wrong := f.a.Runner, []string{}, false
				f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
					command := strings.Join(args, " ")
					if strings.Contains(command, "route get ") && strings.Contains(command, " from ") {
						calls = append(calls, command)
						if wrong {
							return []byte(wanted + " dev foreign0"), nil
						}
					}
					return base.Run(ctx, name, args...)
				})
				if err := verifyPolicyEvidence(context.Background(), f.a.Runner, "ip", state); err != nil {
					t.Fatal(err)
				}
				want := "route get " + wanted + " from " + sample + " iif br0 mark 0x20000000"
				if v6 {
					want = "-6 " + want
				}
				if len(calls) != 1 || calls[0] != want {
					t.Fatal("unspecified or wrong default sample arguments", calls, want)
				}
				wrong, calls = true, nil
				if err := verifyPolicyEvidence(context.Background(), f.a.Runner, "ip", state); err == nil || len(calls) != 1 {
					t.Fatal("wrong default path retried or accepted", calls, err)
				}
			})
		}
	}
}

func TestManagedDefaultDestinationRefusesUnavailableOrUnqualifiedScope(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		state := managedPolicyFixture()
		state.Rules = state.Rules[:1]
		destination := "0.0.0.0/0"
		if v6 {
			destination, state.Rules[0].Source = "::/0", "fd00::40/128"
		}
		state.Rules[0].Destination = destination
		prefix := netip.MustParsePrefix(destination)
		for _, change := range []string{"all-excluded", "bad-exclusion", "legacy", "override", "unmarked", "missing-ingress"} {
			bad := state
			bad.Rules = append([]PolicyRule(nil), state.Rules...)
			switch change {
			case "all-excluded":
				bad.Exclusions = []string{destination}
			case "bad-exclusion":
				bad.Exclusions = []string{"not-a-prefix"}
			case "legacy":
				bad.NetworkPolicyGeneration = ""
			case "override":
				bad.NetworkDefault = false
			case "unmarked":
				bad.Rules[0].Managed = false
			case "missing-ingress":
				bad.Rules[0].Ingress = ""
			}
			if _, err := policyEvidenceDestination(bad, bad.Rules[0], prefix); err == nil {
				t.Fatal("unqualified default sample accepted", v6, change)
			}
		}
	}
}
