package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

type proxyLANFixture struct {
	a            *ProxyTunnelAdapter
	main4, main6 string
	addresses    map[string]string
	members      map[string][]string
}

func newProxyLANFixture(t *testing.T) *proxyLANFixture {
	t.Helper()
	a, _, _ := proxyForwardingFixture(t)
	f := &proxyLANFixture{a: a,
		main4: "default via 100.64.128.1 dev eth3 metric 1000\n10.8.1.0/24 dev nwg0 scope link src 10.8.1.141\n100.64.128.0/17 dev eth3 scope link src 100.64.181.129\n172.16.1.0/24 dev br1 scope link src 172.16.1.1\n192.168.1.0/24 dev br0 scope link src 192.168.1.1\n",
		main6: "fd84:db59:da10::/64 dev br0 metric 256\nfe80::/64 dev br0 metric 256\n",
		addresses: map[string]string{
			"br0": "35: br0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue\n inet 192.168.1.1/24 brd 192.168.1.255 scope global br0\n inet6 fd84:db59:da10:0:d69c:53ff:fe20:b3a7/64 scope global\n inet6 fe80::d69c:53ff:fe20:b3a7/64 scope link\n valid_lft forever preferred_lft forever\n",
			"br1": "36: br1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n inet 172.16.1.1/24 scope global br1\n",
		}, members: map[string][]string{"br0": {"eth2.1", "eth4", "ra0", "ra7.1", "rai0", "rai7.1"}, "br1": {"guest0"}},
	}
	a.LANBridgeMembers = func(_ context.Context, iface string) ([]string, error) { return f.members[iface], nil }
	base := a.Runner
	a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name != "ip" {
			return base.Run(ctx, name, args...)
		}
		v6 := len(args) > 0 && args[0] == "-6"
		if v6 {
			args = args[1:]
		}
		command := strings.Join(args, " ")
		main := f.main4
		if v6 {
			main = f.main6
		}
		if strings.HasPrefix(command, "route show table main") {
			return []byte(main), nil
		}
		if strings.HasPrefix(command, "addr show dev ") {
			return []byte(f.addresses[args[len(args)-1]]), nil
		}
		if len(args) >= 3 && args[0] == "route" && args[1] == "get" {
			if len(args) > 3 {
				return []byte(args[2] + " dev " + a.Interface), nil
			}
			source, err := netip.ParseAddr(args[2])
			if err != nil {
				return nil, err
			}
			for _, network := range []struct{ prefix, iface, local string }{{"192.168.1.0/24", "br0", "192.168.1.1"}, {"172.16.1.0/24", "br1", "172.16.1.1"}, {"fd84:db59:da10::/64", "br0", "fd84:db59:da10::1"}} {
				if netip.MustParsePrefix(network.prefix).Contains(source) {
					if source.String() == network.local {
						return []byte("local " + source.String() + " dev lo"), nil
					}
					return []byte(source.String() + " dev " + network.iface), nil
				}
			}
			return nil, errors.New("unknown fixture source")
		}
		if v6 {
			args = append([]string{"-6"}, args...)
		}
		return base.Run(ctx, name, args...)
	})
	return f
}

func (f *proxyLANFixture) policy(v6 bool, source string) PolicyState {
	destination := "198.51.100.20/32"
	if v6 {
		destination = "2001:db8::20/128"
	}
	return PolicyState{Interface: f.a.Interface, Table: f.a.Table, PriorityBase: f.a.Priority, Prefixes: []string{destination}, Rules: []PolicyRule{{Source: source, Destination: destination}}}
}

func TestProxyAllLANExpandsOnlyAssignedPrivateBridgePrefixes(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprint(v6), func(t *testing.T) {
			f := newProxyLANFixture(t)
			state := f.policy(v6, "")
			if err := f.a.prepareForwarding(context.Background(), &state); err != nil {
				t.Fatal(err)
			}
			want := 2
			if v6 {
				want = 1
			}
			if len(state.Rules) != want {
				t.Fatalf("LAN rule count=%d want=%d", len(state.Rules), want)
			}
			for _, rule := range state.Rules {
				if rule.Source == "" || rule.Source == "0.0.0.0/0" || rule.Source == "::/0" {
					t.Fatal("allLAN retained a global routing rule")
				}
			}
			if err := f.a.installForwarding(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			if err := verifyPolicyEvidence(context.Background(), f.a.Runner, f.a.ip(), state); err != nil {
				t.Fatalf("forwarded subnet route probe failed: %v", err)
			}
			if err := f.a.verifyForwarding(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			if err := f.a.removeForwarding(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProxyLANSubnetMustFitOneAssignedBridgePrefix(t *testing.T) {
	for _, tc := range []struct {
		source string
		ok     bool
	}{{"192.168.1.128/25", true}, {"192.168.1.0/24", true}, {"192.168.0.0/23", false}, {"192.168.2.0/24", false}, {"10.8.1.0/24", false}, {"10.0.0.0/7", false}, {"fd84:db59:da10::/80", true}, {"fd84:db59::/32", false}} {
		t.Run(tc.source, func(t *testing.T) {
			f := newProxyLANFixture(t)
			state := f.policy(strings.Contains(tc.source, ":"), tc.source)
			err := f.a.prepareForwarding(context.Background(), &state)
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%t err=%v", tc.ok, err)
			}
		})
	}
}

func TestProxyLANRejectsWANBridgeAndWANMember(t *testing.T) {
	for _, wan := range []string{"br0", "eth2.1"} {
		t.Run(wan, func(t *testing.T) {
			f := newProxyLANFixture(t)
			f.main6 += "default via fe80::1 dev " + wan + " metric 1024\n"
			state := f.policy(false, "192.168.1.0/24")
			if err := f.a.prepareForwarding(context.Background(), &state); err == nil {
				t.Fatal("WAN bridge subnet received client authority")
			}
		})
	}
}

func TestProxyLANDirectRouteNeedsAssignedAddressAndUPBridge(t *testing.T) {
	for _, mode := range []string{"no-bridge", "no-ports", "down", "wrong-address", "wrong-header", "gateway", "overlap"} {
		t.Run(mode, func(t *testing.T) {
			f := newProxyLANFixture(t)
			switch mode {
			case "no-bridge", "no-ports":
				f.members["br0"] = nil
			case "down":
				f.addresses["br0"] = strings.ReplaceAll(f.addresses["br0"], ",UP,", ",")
			case "wrong-address":
				f.addresses["br0"] = strings.ReplaceAll(f.addresses["br0"], "192.168.1.1/24", "192.168.2.1/24")
			case "wrong-header":
				f.addresses["br0"] = strings.ReplaceAll(f.addresses["br0"], "35: br0:", "35: br9:")
			case "gateway":
				f.main4 = strings.ReplaceAll(f.main4, "192.168.1.0/24 dev br0", "192.168.1.0/24 via 192.168.2.1 dev br0")
			case "overlap":
				f.main4 += "192.168.1.0/24 dev br1 scope link src 192.168.1.254\n"
				f.addresses["br1"] += " inet 192.168.1.254/24 scope global br1\n"
			}
			state := f.policy(false, "192.168.1.0/24")
			if err := f.a.prepareForwarding(context.Background(), &state); err == nil {
				t.Fatal("unproven LAN prefix granted")
			}
		})
	}
}

func TestProxyLANAddressReplacementInvalidatesCommittedGrant(t *testing.T) {
	f := newProxyLANFixture(t)
	state := f.policy(false, "192.168.1.0/24")
	if err := f.a.prepareForwarding(context.Background(), &state); err != nil {
		t.Fatal(err)
	}
	if err := f.a.installForwarding(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	f.addresses["br0"] = strings.ReplaceAll(f.addresses["br0"], "192.168.1.1/24", "192.168.2.1/24")
	if err := f.a.verifyForwarding(context.Background(), state); err == nil {
		t.Fatal("changed LAN identity retained grant authority")
	}
	if err := f.a.removeForwarding(context.Background()); err != nil {
		t.Fatalf("changed LAN prevented exact own cleanup: %v", err)
	}
}

func TestProxyLANDiscoveryIsBoundedAndCanceled(t *testing.T) {
	f := newProxyLANFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.a.connectedLANPrefixes(ctx, false); err == nil {
		t.Fatal("canceled LAN discovery passed")
	}
	f.main4 = strings.Repeat("192.168.1.0/24 dev br0 scope link\n", 17000)
	if _, err := f.a.connectedLANPrefixes(context.Background(), false); err == nil {
		t.Fatal("unbounded main table accepted")
	}
}
