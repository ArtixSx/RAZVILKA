//go:build linux

package dataplane

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type lanNativeLink struct {
	Name   string `json:"ifname"`
	Master string `json:"master"`
	Info   struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

// The coordinator runs this inside an exclusively assigned EMPTY netns.
// This verifies actual Ethernet ingress/MAC marking, RPDB, both address
// families and preservation of a firmware-like foreign route. It does not
// attest a VPN server, DNS redirect, NFQWS daemon or a physical router.
func TestNativeLANPolicyMACGate(t *testing.T) {
	lanNativePolicyGate(t, false)
}

func TestNativeLANPolicySuspension(t *testing.T) {
	lanNativePolicyGate(t, true)
}

func lanNativePolicyGate(t *testing.T, suspension bool) {
	if os.Getenv("RAZVILKA_LAN_POLICY_NETNS") != "1" {
		t.Skip("requires an exclusively assigned empty Linux network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("requires only loopback; refusing network mutations")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	ipt, err := exec.LookPath("iptables")
	if err != nil {
		t.Fatal(err)
	}
	ip6t, err := exec.LookPath("ip6tables")
	if err != nil {
		t.Fatal(err)
	}
	run := func(tool string, args ...string) string {
		t.Helper()
		out, err := exec.Command(tool, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v: %s", tool, args, err, out)
		}
		return string(out)
	}
	run(ip, "link", "set", "lo", "up")
	run(ip, "link", "add", "br-lan", "type", "bridge")
	t.Cleanup(func() { run(ip, "link", "del", "br-lan") })
	run(ip, "link", "set", "br-lan", "up")
	run(ip, "link", "add", "rz-lan-c", "type", "veth", "peer", "name", "rz-lan-r")
	t.Cleanup(func() { run(ip, "link", "del", "rz-lan-c") })
	run(ip, "link", "set", "rz-lan-r", "master", "br-lan")
	for _, name := range []string{"rz-lan-c", "rz-lan-r"} {
		run(ip, "link", "set", name, "up")
	}
	run(ip, "addr", "add", "192.168.77.1/24", "dev", "br-lan")
	run(ip, "-6", "addr", "add", "fd00:77::1/64", "dev", "br-lan", "nodad")
	for _, name := range []string{"rz-svc", "rz-fw"} {
		run(ip, "link", "add", name, "type", "dummy")
		t.Cleanup(func() { run(ip, "link", "del", name) })
		run(ip, "link", "set", name, "up")
	}
	for _, family := range []string{"-4", "-6"} {
		run(ip, family, "route", "add", "default", "dev", "rz-fw", "table", "220")
		run(ip, family, "rule", "add", "priority", "100", "lookup", "220")
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/br-lan/rp_filter", []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := CompileLANPolicyRuntime(strings.Repeat("b", 64), []LANPolicyIngress{{SegmentID: "home", Interface: "br-lan", Sources: []string{"192.168.77.0/24", "fd00:77::/64"}, Membership: "mac", IncludedMACs: []string{"02:00:00:00:00:01"}, ExcludedMACs: []string{"02:00:00:00:00:02"}}})
	if err != nil {
		t.Fatal(err)
	}
	var acknowledged []LANPolicyEffect
	dump := func(stage string, cause error) {
		t.Helper()
		plan, _ := json.MarshalIndent(p, "", "  ")
		effects, _ := p.Effects()
		expected, _ := json.MarshalIndent(effects, "", "  ")
		t.Logf("LAN phase=%s acknowledged=%d/%d cause=%v\nexpected plan=%s\nexpected effects=%s", stage, len(acknowledged), len(effects), cause, plan, expected)
		inspect := func(tool string, args ...string) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			actual, err := exec.CommandContext(ctx, tool, args...).CombinedOutput()
			if len(actual) > 256<<10 {
				actual = actual[:256<<10]
			}
			t.Logf("actual %s %v error=%v\n%s", tool, args, err, actual)
		}
		inspect(ip, "-j", "-d", "link", "show")
		inspect(ip, "-4", "-N", "rule", "show")
		inspect(ip, "-6", "-N", "rule", "show")
		for _, tool := range []string{ipt, ip6t} {
			for _, table := range []string{"mangle", "nat", "filter", "raw"} {
				inspect(tool, "-t", table, "-S")
			}
		}
		sysfsMembers, sysfsErr := linuxBridgeMembers(context.Background(), "br-lan")
		t.Logf("sysfs bridge members=%v error=%v (sysfs mount may belong to another netns)", sysfsMembers, sysfsErr)
	}
	readLinks := func(ctx context.Context, args ...string) ([]lanNativeLink, error) {
		var links []lanNativeLink
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		data, err := exec.CommandContext(ctx, ip, args...).CombinedOutput()
		if err != nil || len(data) > 256<<10 {
			return nil, fmt.Errorf("netns link readback %v: %v: %s", args, err, data)
		}
		if err := json.Unmarshal(data, &links); err != nil {
			return nil, err
		}
		return links, nil
	}
	r := &LANPolicyRuntime{Runner: nfqws2ExecRunner{}, IP: ip, IPTables: ipt, IP6Tables: ip6t, ScopeCheck: func(ctx context.Context, p *LANPolicyRuntimePlan) error {
		iface, err := net.InterfaceByName(p.Ingress[0].Interface)
		if err != nil || iface.Flags&net.FlagUp == 0 {
			return fmt.Errorf("scope interface expected up %s, actual=%v: %v", p.Ingress[0].Interface, iface, err)
		}
		// sysfs is tied to its mount's network namespace. The coordinator's
		// netns need not remount it, so prove fixture bridge identity/member
		// through netlink in this actual namespace instead of a host mount.
		bridge, err := readLinks(ctx, "-j", "-d", "link", "show", "dev", iface.Name)
		if err != nil || len(bridge) != 1 || bridge[0].Name != iface.Name || bridge[0].Info.Kind != "bridge" {
			return fmt.Errorf("scope bridge expected %s kind bridge, actual=%+v: %v", iface.Name, bridge, err)
		}
		members, err := readLinks(ctx, "-j", "link", "show", "master", iface.Name)
		if err != nil || len(members) != 1 || members[0].Name != "rz-lan-r" || members[0].Master != iface.Name {
			return fmt.Errorf("scope member expected rz-lan-r master %s, actual=%+v: %v", iface.Name, members, err)
		}
		return nil
	}}
	// Fixture acknowledgements are process-local. Production uses VLESS's
	// existing common durable addition receipt; this is kernel acceptance only.
	r.Execute = func(ctx context.Context, p *LANPolicyRuntimePlan, effects []LANPolicyEffect) error {
		for _, effect := range effects {
			count, foreign, err := r.InspectEffect(ctx, p, effect)
			if err != nil || foreign || count != 0 {
				return fmt.Errorf("pre-add count=%d foreign=%v: %w", count, foreign, err)
			}
			if _, err := r.Runner.Run(ctx, r.command(effect.Tool), effect.Add...); err != nil {
				return err
			}
			acknowledged = append(acknowledged, effect)
		}
		return nil
	}
	t.Cleanup(func() {
		for i := len(acknowledged) - 1; i >= 0; i-- {
			e := acknowledged[i]
			run(r.command(e.Tool), e.Delete...)
		}
	})
	activate := func() error { return r.Activate(context.Background(), p) }
	var priorRoot string
	if suspension {
		priorRoot = privateScopedXrayFixtureDir(t)
		guard := func(ctx context.Context, _ *LANPolicyRuntimePlan, _ LANPolicyEffect) error { return ctx.Err() }
		gate := &LANPolicyReceiptBinding{Runtime: r, ApplyGuard: guard, CleanupGuard: guard, RetireCheck: func(ctx context.Context, _ *LANPolicyRuntimePlan) error { return ctx.Err() }}
		activate = func() error { return gate.Apply(context.Background(), p, priorRoot) }
		t.Cleanup(func() {
			if err := gate.Remove(context.Background(), p, priorRoot); err != nil {
				dump("receipt gate cleanup", err)
				t.Error(err)
			}
		})
	}
	if err := activate(); err != nil {
		dump("activate", err)
		t.Fatal(err)
	}
	for _, family := range []string{"-4", "-6"} {
		run(ip, family, "route", "add", "default", "dev", "rz-svc", "table", "201")
		run(ip, family, "rule", "add", "priority", "61", "fwmark", "0x20000000/0x28000000", "iif", "br-lan", "lookup", "201")
		if suspension {
			family := family
			t.Cleanup(func() {
				run(ip, family, "rule", "del", "priority", "61", "fwmark", "0x20000000/0x28000000", "iif", "br-lan", "lookup", "201")
			})
		}
	}
	r.ConsumerCheck = func(context.Context, *LANPolicyRuntimePlan) error { return nil } // fixture-owned exact selectors above
	if err := r.Verify(context.Background(), p); err != nil {
		dump("verify with consumers", err)
		t.Fatal(err)
	}
	for _, tool := range []string{ipt, ip6t} {
		for _, out := range []string{"rz-svc", "rz-fw"} {
			run(tool, "-t", "filter", "-A", "FORWARD", "-i", "br-lan", "-o", out, "-p", "udp", "--dport", "19408", "-j", "ACCEPT")
		}
	}
	bridge, err := net.InterfaceByName("br-lan")
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.InterfaceByName("rz-lan-c")
	if err != nil {
		t.Fatal(err)
	}
	counts := func(tool string) (int, int) {
		text := run(tool, "-t", "filter", "-L", "FORWARD", "-v", "-n", "-x")
		selected, firmware := 0, 0
		for _, line := range strings.Split(text, "\n") {
			f := strings.Fields(line)
			if len(f) < 7 || !strings.Contains(line, "dpt:19408") {
				continue
			}
			n, err := strconv.Atoi(f[0])
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(line, "rz-svc") {
				selected += n
			} else if strings.Contains(line, "rz-fw") {
				firmware += n
			}
		}
		return selected, firmware
	}
	for _, v6 := range []bool{false, true} {
		tool, source, destination := ipt, "192.168.77.42", "198.51.100.88"
		if v6 {
			tool, source, destination = ip6t, "fd00:77::1234", "2001:db8:88::8"
		}
		for _, device := range []struct {
			name    string
			mac     byte
			outside bool
		}{{"selected", 1, false}, {"excluded", 2, true}, {"unknown", 3, true}} {
			beforeS, beforeF := counts(tool)
			mac := net.HardwareAddr{2, 0, 0, 0, 0, device.mac}
			if device.outside {
				if v6 {
					source = "fd00:77::9876:abcd"
				}
			} // absent from reviewed leases
			packet := lanNativeUDPFrame(bridge.HardwareAddr, mac, netip.MustParseAddr(source), netip.MustParseAddr(destination))
			fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(unix.ETH_P_ALL))
			if err != nil {
				t.Fatal(err)
			}
			err = unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: client.Index, Protocol: uint16((unix.ETH_P_ALL<<8)&0xff00 | unix.ETH_P_ALL>>8)})
			_ = unix.Close(fd)
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				afterS, afterF := counts(tool)
				if device.outside && afterF > beforeF && afterS == beforeS || !device.outside && afterS > beforeS && afterF == beforeF {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("v6=%v device=%s selected %d→%d firmware %d→%d", v6, device.name, beforeS, afterS, beforeF, afterF)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
	// Exact device negatives skip service61 but continue firmware100; no
	// blanket main lookup, router-output marks or flush were introduced.
	for _, family := range []string{"-4", "-6"} {
		if !strings.Contains(run(ip, family, "rule", "show"), "100:") {
			t.Fatal("foreign firmware selector lost")
		}
	}
	if suspension {
		lanNativeSuspensionFrames(t, r, p, priorRoot, bridge, client, counts, run)
	}
}

func lanNativeUDPFrame(dst, src net.HardwareAddr, source, destination netip.Addr) []byte {
	payload := []byte("RAZVILKA D08 native LAN gate")
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], 29408)
	binary.BigEndian.PutUint16(udp[2:], 19408)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)
	frame := make([]byte, 14)
	copy(frame, dst)
	copy(frame[6:], src)
	if source.Is4() {
		binary.BigEndian.PutUint16(frame[12:], 0x0800)
		ip := make([]byte, 20)
		ip[0], ip[8], ip[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
		a, b := source.As4(), destination.As4()
		copy(ip[12:], a[:])
		copy(ip[16:], b[:])
		binary.BigEndian.PutUint16(ip[10:], lanNativeChecksum(ip))
		return append(append(frame, ip...), udp...)
	}
	binary.BigEndian.PutUint16(frame[12:], 0x86dd)
	ip := make([]byte, 40)
	ip[0], ip[6], ip[7] = 0x60, 17, 64
	binary.BigEndian.PutUint16(ip[4:], uint16(len(udp)))
	a, b := source.As16(), destination.As16()
	copy(ip[8:], a[:])
	copy(ip[24:], b[:])
	pseudo := append(append([]byte{}, a[:]...), b[:]...)
	pseudo = append(pseudo, 0, 0, byte(len(udp)>>8), byte(len(udp)), 0, 0, 0, 17)
	sum := lanNativeChecksum(append(pseudo, udp...))
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], sum)
	return append(append(frame, ip...), udp...)
}

func lanNativeChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) > 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
