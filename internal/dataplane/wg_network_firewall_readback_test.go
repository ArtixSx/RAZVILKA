package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// iptables -S omits explicit universe prefixes while preserving every narrower
// source/destination. Exercise that display grammar only; mutations still go to
// the ordinary stateful model and the native fixture uses the actual binaries.
func wgNetworkElidedUniverseReadback(base NFQWS2Runner) NFQWS2Runner {
	return networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		output, err := base.Run(ctx, name, args...)
		if err != nil || name != "iptables" && name != "ip6tables" || len(args) != 3 || args[2] != "-S" {
			return output, err
		}
		lines := strings.Split(string(output), "\n")
		for index, line := range lines {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[0] != "-A" || !strings.Contains(line, "RZP_") {
				continue
			}
			elided := append([]string(nil), fields[:2]...)
			for i := 2; i < len(fields); i += 2 {
				if i+1 >= len(fields) {
					return nil, errors.New("malformed model readback")
				}
				if (fields[i] == "-s" || fields[i] == "-d") && (fields[i+1] == "0.0.0.0/0" || fields[i+1] == "::/0") {
					continue
				}
				elided = append(elided, fields[i], fields[i+1])
			}
			lines[index] = strings.Join(elided, " ")
		}
		return []byte(strings.Join(lines, "\n")), nil
	})
}

func TestWGNetworkFirewallUniverseReadbackRetainsExactFamilyAndSelectors(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		lan, zero, wrongZero, noncanonicalZero, own, foreign := "192.168.77.0/24", "0.0.0.0/0", "::/0", "1.2.3.4/0", "10.66.0.2", "10.66.0.3"
		if v6 {
			lan, zero, wrongZero, noncanonicalZero, own, foreign = "fd01:77::/64", "::/0", "0.0.0.0/0", "::1/0", "fd66::2", "fd66::3"
		}
		out := []string{"-i", "br-net", "-o", "rz-wg", "-s", lan, "-m", "mark", "--mark", LANPolicyGateMatch, "-j", "ACCEPT"}
		back := []string{"-i", "rz-wg", "-o", "br-net", "-d", lan, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
		nat := []string{"-o", "rz-wg", "-s", lan, "-m", "mark", "--mark", LANPolicyGateMatch, "-j", "SNAT", "--to-source", own}
		for _, pair := range []struct {
			actual   []string
			selector string
		}{{out, "-d"}, {back, "-s"}, {nat, "-d"}} {
			planned := append(append([]string(nil), pair.actual...), pair.selector, zero)
			key := wgNetworkFirewallKey(pair.actual, v6)
			if strings.HasPrefix(key, "!") || wgNetworkFirewallKey(planned, v6) != key {
				t.Fatal("same-family universe elision changed exact tuple", v6, pair.selector)
			}
			for _, value := range []string{wrongZero, noncanonicalZero, "::ffff:0.0.0.0/96", "unknown"} {
				changed := append(append([]string(nil), pair.actual...), pair.selector, value)
				if !strings.HasPrefix(wgNetworkFirewallKey(changed, v6), "!") {
					t.Fatal("unknown/family-mismatched prefix was elided", v6, value)
				}
			}
			duplicate := append(append([]string(nil), planned...), pair.selector, zero)
			if !strings.HasPrefix(wgNetworkFirewallKey(duplicate, v6), "!") {
				t.Fatal("duplicate universe selector disappeared", v6)
			}
		}
		changed := append([]string(nil), nat...)
		changed[len(changed)-1] = foreign
		if wgNetworkFirewallKey(changed, v6) == wgNetworkFirewallKey(nat, v6) {
			t.Fatal("foreign SNAT address became owned", v6)
		}
		changed = append([]string(nil), out...)
		changed[5] = zero
		if wgNetworkFirewallKey(changed, v6) == wgNetworkFirewallKey(out, v6) {
			t.Fatal("whole-family source became the owned LAN prefix", v6)
		}
		changed = append([]string(nil), out...)
		changed[9] = "0x20000000/0x20000000"
		if wgNetworkFirewallKey(changed, v6) == wgNetworkFirewallKey(out, v6) {
			t.Fatal("changed mark mask became owned", v6)
		}
		changed = append(append([]string(nil), out[:4]...), out[6:]...)
		if wgNetworkFirewallKey(changed, v6) == wgNetworkFirewallKey(out, v6) {
			t.Fatal("missing LAN source became owned", v6)
		}
		narrow := "198.51.100.10/32"
		if v6 {
			narrow = "2001:db8:10::10/128"
		}
		changed = append(append([]string(nil), out...), "-d", narrow)
		if wgNetworkFirewallKey(changed, v6) == wgNetworkFirewallKey(out, v6) {
			t.Fatal("narrower destination was elided", v6)
		}
		changed = append([]string(nil), nat...)
		changed[len(changed)-1] = "fd66::2"
		if v6 {
			changed[len(changed)-1] = "10.66.0.2"
		}
		if !strings.HasPrefix(wgNetworkFirewallKey(changed, v6), "!") {
			t.Fatal("SNAT readback crossed tool families", v6)
		}
	}
}

func TestWGNetworkKernelElidesUniversePrefixesFromFirewallReadback(t *testing.T) {
	a, kernel, plan, root, ctx := wgNetworkLifecycleFixture(t, true)
	a.Runner = wgNetworkElidedUniverseReadback(a.Runner)
	for _, step := range []struct {
		name string
		run  func(context.Context, Plan, string) error
	}{{"snapshot", a.Snapshot}, {"stage", a.Stage}, {"activate", a.Activate}, {"commit", a.Commit}} {
		if err := step.run(ctx, plan, root); err != nil {
			t.Fatal(step.name, err)
		}
	}
	state, exists, err := a.loadPolicyState()
	if err != nil || !exists {
		t.Fatal("committed state missing", err)
	}
	ref, err := a.committedWGPolicyReference(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.verifyWGNetworkEffectPresence(ctx, ref, 1); err != nil {
		t.Fatal("canonical kernel output refused", err)
	}
	if err := a.Deactivate(ctx); err != nil {
		t.Fatal("receipt-owned cleanup refused canonical kernel output", err)
	}
	if status, err := a.inspectWGPolicyReference(ctx, ref, ""); err != nil || !status.Removed || status.Unknown || kernel.active || len(kernel.policy.defaults) != 0 || len(kernel.policy.entries) != 0 {
		t.Fatal("cleanup did not settle the original receipt", status, err)
	}
}
