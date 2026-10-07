//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/awgprofile"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
	"golang.org/x/net/dns/dnsmessage"
)

// ROOT ONLY: empty dedicated netns, root, private TMPDIR under /etc/wireguard.
// RAZVILKA_WG_NETWORK_NATIVE=1; optionally WG_NETWORK_ENGINE=amneziawg and
// RAZVILKA_AWG_NATIVE_TOOL=<already installed verified AWG 3.1 CLI>.
// No module installation, host configuration, kernel doubles or transport
// success callbacks. The parent is the router; owned children are peer/LAN.
// Peer AllowedIPs contain ONLY own tunnel addresses, never LAN source CIDRs.
// Fixture DNS supplies A/AAAA; production bound TCP/UDP health runs unchanged.
// This is kernel/receipt composition, not ordinary CORE Manager registration.
// The fixture creates the reviewed gate before WG because the standalone LAN
// binding preflight requires an empty consumer namespace; it sends no LAN
// requests until WG has committed. Production manager ordering is not proved.
func TestWGNativeNetworkReceipt(t *testing.T) {
	if os.Getenv("RAZVILKA_WG_NETWORK_NATIVE") != "1" {
		t.Skip("Root-only dedicated empty network namespace")
	}
	if role := os.Getenv("RAZVILKA_WG_NETWORK_ROLE"); role != "" {
		switch role {
		case "peer":
			wgNetworkNativeServe(t)
		case "query":
			wgNetworkNativeQuery(t)
		case "recover":
			root := os.Getenv("RAZVILKA_WG_NETWORK_ROOT")
			var plan Plan
			if err := json.Unmarshal(mustRead(filepath.Join(root, "plan.json")), &plan); err != nil {
				t.Fatal(err)
			}
			a := wgNetworkNativeAdapter(t, root)
			wgNetworkNativeDNS(t, "127.0.0.1:0")
			ctx := wgNetworkNativeContext(a, plan)
			if err := a.Reconcile(ctx, plan); err != nil {
				t.Fatal("fresh process recovery", err)
			}
		default:
			t.Fatal("invalid native network role")
		}
		return
	}
	links, err := net.Interfaces()
	if err != nil || os.Geteuid() != 0 || len(links) != 1 || links[0].Name != "lo" {
		t.Fatal("requires root and exclusively assigned namespace containing only lo")
	}
	for _, tool := range []string{"ip", "wg", "iptables", "ip6tables"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	cli, kind, advanced := "wg", "wireguard", ""
	if engine := os.Getenv("WG_NETWORK_ENGINE"); engine != "" && engine != "wireguard" && engine != "amneziawg" {
		t.Fatal("invalid native network engine")
	}
	if os.Getenv("WG_NETWORK_ENGINE") == "amneziawg" {
		cli = os.Getenv("RAZVILKA_AWG_NATIVE_TOOL")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		caps := awgprofile.DetectTool(ctx, cli)
		if issues := awgprofile.CheckRuntime(awgprofile.Preview{MinimumMajor: 3, MinimumMinor: 1}, caps); len(issues) != 0 {
			cancel()
			t.Fatal("preinstalled advanced AWG required before mutations", issues)
		}
		cli, err = awgprofile.VerifyTool(ctx, caps, cli)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		kind = "amneziawg"
		key, _ := nativeWGKeys(t)
		advanced = "S1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nH1 = 10-20\nH2 = 30-40\nH3 = 50\nH4 = 60\nHeaderProtectionKey = " + key + "\nRandomTrailers = on\nDisableCookies = off\n"
	}
	root := t.TempDir()
	if !strings.HasPrefix(filepath.Clean(root), "/etc/wireguard/") {
		t.Fatal("set private TMPDIR under /etc/wireguard before native setup")
	}
	peerNS, lanNS := fmt.Sprintf("rz-net-p-%d", os.Getpid()), fmt.Sprintf("rz-net-l-%d", os.Getpid())
	run := func(ns string, args ...string) string { return nativeWGCommand(t, ns, args...) }
	for _, ns := range []string{peerNS, lanNS} {
		run("", "ip", "netns", "add", ns)
		t.Cleanup(func() { nativeWGCommand(t, "", "ip", "netns", "del", ns) })
		run(ns, "ip", "link", "set", "lo", "up")
	}
	run("", "ip", "link", "set", "lo", "up")
	run("", "ip", "link", "add", "wan-c", "type", "veth", "peer", "name", "wan-s", "netns", peerNS)
	t.Cleanup(func() { nativeWGCommand(t, "", "ip", "link", "del", "wan-c") })
	run("", "ip", "link", "add", "br-net", "type", "bridge")
	t.Cleanup(func() { nativeWGCommand(t, "", "ip", "link", "del", "br-net") })
	run("", "ip", "link", "add", "lan-r", "type", "veth", "peer", "name", "lan-c", "netns", lanNS)
	t.Cleanup(func() { nativeWGCommand(t, "", "ip", "link", "del", "lan-r") })
	run("", "ip", "link", "set", "lan-r", "master", "br-net")
	run(lanNS, "ip", "link", "set", "lan-c", "address", "02:00:00:00:00:01")
	for _, link := range []struct{ ns, dev, v4, v6 string }{
		{"", "wan-c", "192.0.2.2/30", "2001:db8:1::2/64"}, {peerNS, "wan-s", "192.0.2.1/30", "2001:db8:1::1/64"},
		{"", "br-net", "192.168.77.1/24", "fd01:77::1/64"}, {lanNS, "lan-c", "192.168.77.2/24", "fd01:77::2/64"},
	} {
		run(link.ns, "ip", "addr", "add", link.v4, "dev", link.dev)
		run(link.ns, "ip", "-6", "addr", "add", link.v6, "dev", link.dev, "nodad")
		run(link.ns, "ip", "link", "set", link.dev, "up")
	}
	run("", "ip", "link", "set", "lan-r", "up")
	for _, route := range []struct{ ns, family, target, via, dev string }{
		{"", "-4", "default", "192.0.2.1", "wan-c"}, {"", "-6", "default", "2001:db8:1::1", "wan-c"},
		{lanNS, "-4", "default", "192.168.77.1", "lan-c"}, {lanNS, "-6", "default", "fd01:77::1", "lan-c"},
		{peerNS, "-4", "192.168.77.0/24", "192.0.2.2", "wan-s"}, {peerNS, "-6", "fd01:77::/64", "2001:db8:1::2", "wan-s"},
	} {
		run(route.ns, "ip", route.family, "route", "add", route.target, "via", route.via, "dev", route.dev)
	}
	for path, value := range map[string]string{"/proc/sys/net/ipv4/ip_forward": "1", "/proc/sys/net/ipv6/conf/all/forwarding": "1", "/proc/sys/net/ipv4/conf/all/rp_filter": "0", "/proc/sys/net/ipv4/conf/default/rp_filter": "0", "/proc/sys/net/ipv4/conf/br-net/rp_filter": "0", "/proc/sys/net/ipv4/conf/wan-c/rp_filter": "0", "/proc/sys/net/bridge/bridge-nf-call-iptables": "1", "/proc/sys/net/bridge/bridge-nf-call-ip6tables": "1"} {
		if err := os.WriteFile(path, []byte(value+"\n"), 0600); err != nil {
			t.Fatal("Root must prepare bridge netfilter in this isolated namespace", path, err)
		}
	}
	for _, tool := range []string{"iptables", "ip6tables"} {
		run("", tool, "-P", "FORWARD", "DROP")
		run("", tool, "-A", "FORWARD", "-i", "br-net", "-o", "wan-c", "-j", "ACCEPT")
		run("", tool, "-A", "FORWARD", "-i", "wan-c", "-o", "br-net", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	}
	private, public := nativeWGKeys(t)
	peerPrivate, peerPublic := nativeWGKeys(t)
	server := "[Interface]\nPrivateKey = " + peerPrivate + "\nListenPort = 51820\n" + advanced + "[Peer]\nPublicKey = " + public + "\nAllowedIPs = 10.66.0.2/32, fd66::2/128\n"
	serverPath := filepath.Join(root, "peer.conf")
	if err := os.WriteFile(serverPath, []byte(server), 0600); err != nil {
		t.Fatal(err)
	}
	run(peerNS, "ip", "link", "add", "wg-server", "type", kind)
	run(peerNS, cli, "setconf", "wg-server", serverPath)
	run(peerNS, "ip", "link", "set", "wg-server", "up")
	for _, addr := range []string{"93.184.216.34/32", "198.51.100.10/32", "2001:db8:10::10/128", "1.1.1.1/32", "2606:4700:4700::1111/128"} {
		run(peerNS, "ip", "addr", "add", addr, "dev", "lo", "nodad")
	}
	run(peerNS, "ip", "route", "add", "10.66.0.2/32", "dev", "wg-server")
	run(peerNS, "ip", "-6", "route", "add", "fd66::2/128", "dev", "wg-server")
	wgNetworkNativeChild(t, peerNS, "peer", root, false)
	a := wgNetworkNativeAdapter(t, root)
	profile := "[Interface]\nPrivateKey = " + private + "\nAddress = 10.66.0.2/32, fd66::2/128\n" + advanced + "[Peer]\nPublicKey = " + peerPublic + "\nEndpoint = 93.184.216.34:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
	revision, resolved := "", a.ID()
	if a.ID() == "wireguard" {
		meta, err := a.Profiles.(*wireguardprofile.Store).Put(context.Background(), "native", "native network", profile, "")
		if err != nil {
			t.Fatal(err)
		}
		revision, resolved = meta.Revision, "wireguard:native"
	} else if _, err := a.Configs.Stage(a.ID(), "main", profile); err != nil {
		t.Fatal(err)
	}
	plan := Plan{Routes: []Route{{Resolved: resolved, WireGuardProfileRevision: revision, ServiceName: "native", CIDRs: []string{"0.0.0.0/0", "::/0"}, Sources: []string{"192.168.77.0/24", "fd01:77::/64"}, Ingress: []string{"br-net"}, NetworkPolicyGeneration: strings.Repeat("a", 64), NetworkPolicyRole: "default", ProbeURL: "http://network.native.test/"}}}
	plan.LAN, err = CompileLANPolicyRuntime(plan.Routes[0].NetworkPolicyGeneration, []LANPolicyIngress{{SegmentID: "native", Interface: "br-net", Sources: plan.Routes[0].Sources, Membership: "all", ExcludedMACs: []string{"02:00:00:00:00:02"}}})
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(plan)
	if err := os.WriteFile(filepath.Join(root, "plan.json"), wire, 0600); err != nil {
		t.Fatal(err)
	}
	wgNetworkNativeDNS(t, "127.0.0.1:0")
	ctx := wgNetworkNativeContext(a, plan)
	apply := func(label string) {
		transaction := filepath.Join(root, label)
		previousFault := a.policyReceiptOptions.fault
		a.policyReceiptOptions.fault = func(point string, index int) error {
			t.Logf("native %s receipt checkpoint=%s effect=%d", label, point, index)
			return nil // observe only; no receipt, command or health replacement
		}
		defer func() { a.policyReceiptOptions.fault = previousFault }()
		for _, step := range []struct {
			name string
			run  func(context.Context, Plan, string) error
		}{
			{"snapshot", a.Snapshot}, {"stage", a.Stage}, {"validate", a.Validate},
			{"canary", func(c context.Context, p Plan, root string) error { return a.Canary(c, p.RoutePlanFor(a.ID()), root) }},
			{"activate", a.Activate}, {"health", a.Health}, {"commit", a.Commit},
		} {
			t.Logf("native %s stage=%s begin", label, step.name)
			if err := step.run(ctx, plan, transaction); err != nil {
				wgNetworkNativeDiagnose(t, a, ctx, transaction)
				t.Fatal(label, step.name, err)
			}
			t.Logf("native %s stage=%s passed", label, step.name)
		}
	}
	lan := &LANPolicyRuntime{Runner: a.Runner, IP: a.IP, IPTables: a.IPTables, IP6Tables: a.IP6Tables}
	lan.ScopeCheck = func(c context.Context, p *LANPolicyRuntimePlan) error {
		if !reflect.DeepEqual(p, plan.LAN) {
			return ErrReviewChanged
		}
		return wgNetworkNativeScope(a, c, plan)
	}
	guard := func(c context.Context, p *LANPolicyRuntimePlan, _ LANPolicyEffect) error { return lan.ScopeCheck(c, p) }
	binding := &LANPolicyReceiptBinding{Runtime: lan, ApplyGuard: guard, CleanupGuard: guard, RetireCheck: func(c context.Context, _ *LANPolicyRuntimePlan) error { return a.VerifyRuntimeInactive(c) }}
	if err := os.Mkdir(filepath.Join(root, "lan-receipt"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := binding.Apply(ctx, plan.LAN, filepath.Join(root, "lan-receipt")); err != nil {
		t.Fatal("actual common LAN gate", err)
	}
	apply("first")
	consumerChecks := 0
	lan.ConsumerCheck = func(c context.Context, p *LANPolicyRuntimePlan) error {
		consumerChecks++
		if !reflect.DeepEqual(p, plan.LAN) {
			return ErrReviewChanged
		}
		state, exists, err := a.loadPolicyState()
		if err != nil || !exists {
			return errors.Join(err, ErrPolicyAdditionReceipt)
		}
		ref, err := a.committedWGPolicyReference(state)
		if err != nil {
			return err
		}
		status, err := a.inspectWGPolicyReference(c, ref, "")
		if err != nil || !status.Complete || status.Unknown || status.Removed {
			return errors.Join(err, ErrPolicyAdditionUnknown)
		}
		return a.verifyWGNetworkEffectPresence(c, ref, 1)
	}
	if err := lan.ConsumerCheck(ctx, plan.LAN); err != nil {
		wgNetworkNativeDiagnoseLAN(t, a, lan, ctx, plan.LAN)
		t.Fatal("exact committed real WG consumer", err)
	}
	t.Log("native exact committed real WG consumer passed")
	lan.TransportCheck = a.VerifyLANPolicyTransport
	checksBeforeVerify := consumerChecks
	if err := lan.Verify(ctx, plan.LAN); err != nil {
		t.Logf("native LAN Verify consumer-check calls=%d", consumerChecks-checksBeforeVerify)
		wgNetworkNativeDiagnoseLAN(t, a, lan, ctx, plan.LAN)
		t.Fatal("gate with exact committed real WG consumer", err)
	}
	assertClients := func(mode string) {
		t.Setenv("RAZVILKA_WG_NETWORK_EXPECT", mode)
		wgNetworkNativeChild(t, lanNS, "query", root, true)
	}
	assertClients("tunnel")
	run(lanNS, "ip", "link", "set", "lan-c", "address", "02:00:00:00:00:02")
	for _, address := range []string{"192.168.77.2", "fd01:77::2"} {
		run("", "ip", "neigh", "replace", address, "lladdr", "02:00:00:00:00:02", "dev", "br-net", "nud", "permanent")
	}
	assertClients("baseline")
	run(lanNS, "ip", "-6", "addr", "add", "fd01:77::100/64", "dev", "lan-c", "nodad")
	run("", "ip", "neigh", "replace", "fd01:77::100", "lladdr", "02:00:00:00:00:02", "dev", "br-net", "nud", "permanent")
	t.Setenv("RAZVILKA_WG_NETWORK_PRIVACY", "1")
	assertClients("baseline")
	t.Setenv("RAZVILKA_WG_NETWORK_PRIVACY", "")
	run(lanNS, "ip", "link", "set", "lan-c", "address", "02:00:00:00:00:01")
	for _, address := range []string{"192.168.77.2", "fd01:77::2"} {
		run("", "ip", "neigh", "replace", address, "lladdr", "02:00:00:00:00:01", "dev", "br-net", "nud", "permanent")
	}
	assertClients("tunnel")
	before := run("", "ip", "-j", "link", "show", "dev", a.interfaceName())
	second := filepath.Join(root, "same-peer")
	for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Validate} {
		if err := step(ctx, plan, second); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Canary(ctx, plan.RoutePlanFor(a.ID()), second); err != nil {
		t.Fatal("same-peer live canary", err)
	}
	wgNetworkNativeChild(t, "", "recover", root, true)
	if before != run("", "ip", "-j", "link", "show", "dev", a.interfaceName()) {
		t.Fatal("healthy process restart or same-peer canary replaced interface")
	}
	assertClients("tunnel")
	state, exists, err := a.loadPolicyState()
	if err != nil || !exists {
		t.Fatal("committed network state missing", err)
	}
	ref, err := a.committedWGPolicyReference(state)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := a.compileWGNetworkEffects(ref)
	if err != nil {
		t.Fatal(err)
	}
	last := len(compiled.plan.Effects) - 1
	a.policyReceiptOptions.fault = func(point string, index int) error {
		if point == "removed" && index == last {
			return errors.New("native durable removal ACK cut")
		}
		return nil
	}
	if err := a.Deactivate(ctx); err == nil {
		t.Fatal("known cut missing")
	}
	for _, family := range []int{4, 6} {
		if count, err := a.wgNetworkServiceTablePresence(ctx, state, family); err != nil || count != 1 {
			t.Fatal("cut lost routing prerequisite", family, err)
		}
	}
	a.policyReceiptOptions.fault = nil
	if err := a.Deactivate(ctx); err != nil {
		t.Fatal("known removal retry", err)
	}
	if status, err := a.inspectWGPolicyReference(ctx, ref, ""); err != nil || !status.Removed || status.Unknown {
		t.Fatal("known removal receipt did not settle", status, err)
	}
	if err := a.wgPolicyAbsent(ctx, ref); err != nil || a.interfaceActive(ctx) {
		t.Fatal("known retry left owned effects or interface", err)
	}
	apply("unknown-cut")
	state, exists, err = a.loadPolicyState()
	if err != nil || !exists {
		t.Fatal("unknown-cut state missing", err)
	}
	ref, err = a.committedWGPolicyReference(state)
	if err != nil {
		t.Fatal(err)
	}
	a.policyReceiptOptions.fault = func(point string, index int) error {
		if point == "cleanup-intent" && index == last {
			return errors.New("native unknown filter removal")
		}
		return nil
	}
	if err := a.Deactivate(ctx); err == nil {
		t.Fatal("unknown cut missing")
	}
	a.policyReceiptOptions.fault = nil
	if err := a.Deactivate(ctx); !errors.Is(err, ErrPolicyAdditionUnknown) {
		t.Fatal("unknown removal retried from kernel coincidence", err)
	}
	if status, err := a.inspectWGPolicyReference(ctx, ref, ""); err != nil || !status.Unknown || status.Removed {
		t.Fatal("unknown consumer receipt was lost", status, err)
	}
	for _, family := range []int{4, 6} {
		if count, err := a.wgNetworkServiceTablePresence(ctx, state, family); err != nil || count != 1 || !a.interfaceActive(ctx) {
			t.Fatal("unknown removal lost routing or interface", family, err)
		}
	}
	if err := binding.Remove(ctx, plan.LAN, filepath.Join(root, "lan-receipt")); !errors.Is(err, errWGInactiveUnknown) {
		t.Fatal("gate retirement did not retain unknown WG consumer", err)
	}
	if status, err := binding.Inspect(ctx, plan.LAN, filepath.Join(root, "lan-receipt")); err != nil || !status.Complete || status.Unknown || status.Removed {
		t.Fatal("gate receipt changed under unknown consumer", status, err)
	}
	gateEffects, err := plan.LAN.Effects()
	if err != nil {
		t.Fatal(err)
	}
	for _, effect := range gateEffects {
		if count, foreign, err := lan.InspectEffect(ctx, plan.LAN, effect); err != nil || foreign || count != 1 {
			t.Fatal("gate kernel effects changed under unknown consumer", err)
		}
	}
	t.Log("actual dual-family LAN TCP/UDP source NAT; excluded MAC/privacy baseline; same-peer/fresh process; known/unknown receipt cuts passed")
}

// Observe the actual committed transport selector without changing the LAN
// verifier or accepting a foreign rule. Log only receipt-reconstructed public
// values after the strict endpoint matcher has recognized the native row.
func wgNetworkNativeDiagnoseLAN(t *testing.T, a *WARPWireGuardAdapter, lan *LANPolicyRuntime, ctx context.Context, plan *LANPolicyRuntimePlan) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
	defer cancel()
	t.Log("native LAN diagnostic physical scope", lan.ScopeCheck(ctx, plan))
	state, exists, err := a.loadPolicyState()
	if err != nil || !exists {
		t.Log("native LAN diagnostic committed-state unavailable", err)
		return
	}
	ref, err := a.committedWGPolicyReference(state)
	if err != nil || state.WireGuardEndpoint == nil {
		t.Log("native LAN diagnostic committed-reference unavailable", err)
		return
	}
	e := state.WireGuardEndpoint
	t.Log("native LAN diagnostic exact transport proof", a.verifyWGEndpoint(ctx, e, ref.FrozenLAN))
	serviceTable := false
	for _, owner := range PolicyOwnershipSpecs() {
		serviceTable = serviceTable || owner.Table == e.Table
	}
	for _, family := range []int{4, 6} {
		lines, err := readPolicyRules(ctx, a.Runner, a.ip(), family)
		if err != nil {
			t.Logf("native LAN diagnostic RPDB family=%d read-error=%v", family, err)
			return
		}
		matched, badSyntax := 0, 0
		for _, line := range lines {
			if !lanPolicyRuleSyntax(line) {
				badSyntax++
			}
			if !e.matchesRule(family, line) {
				continue
			}
			matched++
			fields := strings.Fields(line)
			for index, value := range fields {
				if value == "fwmark" && index+1 < len(fields) {
					t.Logf("native LAN diagnostic exact endpoint row family=%d priority=%d mark=0x%x mask=0xffffffff table=%d lan-mark-touches=%t skip-priority=%t service-table=%t syntax=%t", family, e.Priority, e.Mark, e.Table, lanPolicyMarkTouches(fields[index+1]), e.Priority == LANPolicySkipPriority, serviceTable, lanPolicyRuleSyntax(line))
				}
			}
		}
		t.Logf("native LAN diagnostic RPDB family=%d endpoint-count=%d bad-syntax=%d", family, matched, badSyntax)
	}
}

// Bounded, read-only diagnostics from reconstructed immutable intent. Never
// print profile/config bytes, wg output, receipt argv or arbitrary CLI output.
func wgNetworkNativeDiagnose(t *testing.T, a *WARPWireGuardAdapter, ctx context.Context, transaction string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
	defer cancel()
	state, err := a.readStagedPolicy(transaction)
	if err != nil {
		t.Log("native diagnostic staged-state unavailable", err)
		return
	}
	for _, family := range []int{4, 6} {
		data, readErr := a.readWGCompleteDetailedNumericTable(ctx, state.Table, family)
		rows, parseErr := parseWGEndpointRoutes(data)
		t.Logf("native diagnostic detailed service family=%d rows=%d read-error=%v parse-error=%v", family, len(rows), readErr, parseErr)
		if readErr == nil && parseErr == nil && len(rows) == 1 {
			row := rows[0]
			t.Logf("native diagnostic service family=%d unicast=%t boot=%t link-scope=%t global-scope=%t metric=%d own-device=%t gateway=%t source=%t selected-source=%t from=%t flags=%d", family, row.Type == "unicast", row.Protocol == "boot", row.Scope == "link", row.Scope == "global", row.Metric, row.Device == state.Interface, row.Gateway != "", row.Source != "", row.SelectedSource != "", row.From != "", len(row.Flags))
		}
	}
	ref, exists, err := a.readWGPolicyReference(transaction, state, false)
	if err != nil || !exists {
		t.Log("native diagnostic candidate-reference unavailable", err)
		return
	}
	status, err := a.inspectWGPolicyReference(ctx, ref, transaction)
	t.Logf("native diagnostic receipt complete=%t unknown=%t removed=%t added=%d pending=%d cleaned=%d error=%v", status.Complete, status.Unknown, status.Removed, status.Added, status.Pending, status.Cleaned, err)
	compiled, err := a.compileWGNetworkEffects(ref)
	if err != nil {
		t.Log("native diagnostic effect-compiler unavailable", err)
		return
	}
	runtime := a.wgNetworkEffectRuntime(ref, compiled, false)
	for index, effect := range compiled.plan.Effects {
		count, err := runtime.ExactPresence(ctx, index)
		t.Logf("native diagnostic effect=%d tool=%s count=%d error=%v", index, effect.Tool, count, err)
		if ctx.Err() != nil {
			return
		}
	}
}

func wgNetworkNativeAdapter(t *testing.T, root string) *WARPWireGuardAdapter {
	configs := engineconfig.New(filepath.Join(root, "configs"), filepath.Join(root, "backups"))
	configs.LiveRoot = filepath.Join(root, "live")
	a := NewWireGuardAdapter(configs, root)
	if os.Getenv("WG_NETWORK_ENGINE") == "amneziawg" {
		a = NewAmneziaWGAdapter(configs, root)
		a.WG = os.Getenv("RAZVILKA_AWG_NATIVE_TOOL")
	} else {
		a.WG = "wg"
	}
	a.IP, a.IPTables, a.IP6Tables, a.NativeOnly = "ip", "iptables", "ip6tables", true
	a.RuntimeConfigPath = filepath.Join(root, a.interfaceName()+".conf")
	a.Profiles = wireguardprofile.New(filepath.Join(root, "profiles"))
	a.networkLANBridgeMembers = wgNetworkNativeMembers
	return a
}

func wgNetworkNativeMembers(ctx context.Context, name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, "ip", "-j", "-d", "link", "show", "dev", name).Output()
	var bridge []lanNativeLink
	if err != nil || len(data) > 256<<10 || json.Unmarshal(data, &bridge) != nil || len(bridge) != 1 || bridge[0].Info.Kind != "bridge" {
		return nil, ErrReviewChanged
	}
	data, err = exec.CommandContext(ctx, "ip", "-j", "link", "show", "master", name).Output()
	var members []lanNativeLink
	if err != nil || len(data) > 256<<10 || json.Unmarshal(data, &members) != nil || len(members) != 1 || members[0].Name != "lan-r" || members[0].Master != name {
		return nil, ErrReviewChanged
	}
	return []string{"lan-r"}, nil
}

func wgNetworkNativeScope(a *WARPWireGuardAdapter, ctx context.Context, plan Plan) error {
	if ValidateNetworkPolicyLAN(plan.LAN, plan.Routes) != nil {
		return ErrReviewChanged
	}
	for _, v6 := range []bool{false, true} {
		prefixes, err := a.wgForwardingObserver().connectedLANPrefixes(ctx, v6)
		if err != nil {
			return err
		}
		for _, source := range plan.Routes[0].Sources {
			p := netip.MustParsePrefix(source)
			if p.Addr().Is6() == v6 {
				iif, err := connectedLANIngress(prefixes, p)
				if err != nil || iif != "br-net" {
					return ErrReviewChanged
				}
			}
		}
	}
	return ctx.Err()
}

func wgNetworkNativeContext(a *WARPWireGuardAdapter, plan Plan) context.Context {
	return context.WithValue(context.Background(), reviewGuardKey{}, func(c context.Context) error { return wgNetworkNativeScope(a, c, plan) })
}

func wgNetworkNativeChild(t *testing.T, ns, role, root string, wait bool) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if wait {
		cancel()
		ctx, cancel = context.WithTimeout(context.Background(), 45*time.Second)
	}
	args := []string{exe, "-test.run=^TestWGNativeNetworkReceipt$", "-test.v"}
	if ns != "" {
		args = append([]string{"ip", "netns", "exec", ns}, args...)
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "RAZVILKA_WG_NETWORK_ROLE="+role, "RAZVILKA_WG_NETWORK_ROOT="+root)
	if wait {
		defer cancel()
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("native %s: %v\n%s", role, err, output)
		}
		t.Log(string(output))
		return
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for !regularFile(filepath.Join(root, "peer-ready")) {
		if time.Now().After(deadline) {
			t.Fatal("peer server readiness timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func wgNetworkNativeServe(t *testing.T) {
	for _, address := range []string{"198.51.100.10", "2001:db8:10::10"} {
		listener, err := net.Listen("tcp", net.JoinHostPort(address, "80"))
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			_, _ = io.WriteString(w, host)
		}))
		conn, err := net.ListenPacket("udp", net.JoinHostPort(address, "35001"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		go func() {
			buffer := make([]byte, 256)
			for {
				n, peer, err := conn.ReadFrom(buffer)
				if err != nil {
					return
				}
				host, _, _ := net.SplitHostPort(peer.String())
				_, _ = conn.WriteTo(append(append([]byte{}, buffer[:n]...), []byte("|"+host)...), peer)
			}
		}()
	}
	for _, address := range []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53"} {
		wgNetworkNativeDNSListener(t, address)
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("RAZVILKA_WG_NETWORK_ROOT"), "peer-ready"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	select {}
}

func wgNetworkNativeDNSListener(t *testing.T, address string) string {
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, peer, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil || len(query.Questions) != 1 {
				continue
			}
			q := query.Questions[0]
			reply := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionDesired: query.RecursionDesired, RecursionAvailable: true}, Questions: query.Questions}
			h := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 60}
			switch q.Type {
			case dnsmessage.TypeA:
				reply.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AResource{A: [4]byte{198, 51, 100, 10}}}}
			case dnsmessage.TypeAAAA:
				reply.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8:10::10").As16()}}}
			}
			if string(q.Name.Data[:q.Name.Length]) == "www.cloudflare.com." {
				if q.Type == dnsmessage.TypeA {
					reply.Answers[0].Body = &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}
				} else if q.Type == dnsmessage.TypeAAAA {
					reply.Answers[0].Body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700:4700::1111").As16()}
				}
			}
			wire, err := reply.Pack()
			if err == nil {
				_, _ = conn.WriteTo(wire, peer)
			}
		}
	}()
	return conn.LocalAddr().String()
}

func wgNetworkNativeDNS(t *testing.T, address string) {
	endpoint := wgNetworkNativeDNSListener(t, address)
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, endpoint)
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
}

func wgNetworkNativeQuery(t *testing.T) {
	for _, source := range []string{"192.168.77.2", "fd01:77::2"} {
		if source == "fd01:77::2" && os.Getenv("RAZVILKA_WG_NETWORK_PRIVACY") == "1" {
			source = "fd01:77::100"
		}
		address, own, network := "198.51.100.10", "10.66.0.2", "4"
		if strings.Contains(source, ":") {
			address, own, network = "2001:db8:10::10", "fd66::2", "6"
		}
		if os.Getenv("RAZVILKA_WG_NETWORK_EXPECT") == "baseline" {
			own = source
		}
		dialer := &net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
		transport := &http.Transport{Proxy: nil, DialContext: func(c context.Context, _, target string) (net.Conn, error) {
			return dialer.DialContext(c, "tcp"+network, target)
		}}
		client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
		response, err := client.Get("http://" + net.JoinHostPort(address, "80") + "/")
		if err != nil {
			t.Fatal("LAN TCP", source, err)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 256))
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		if err != nil || string(body) != own {
			t.Fatal("TCP server source does not prove selected path", source, string(body), own, err)
		}
		dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP(source)}
		conn, err := dialer.Dial("udp"+network, net.JoinHostPort(address, "35001"))
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		message := "native-full-cidr-" + source
		if _, err := conn.Write([]byte(message)); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		buffer := make([]byte, 256)
		n, err := conn.Read(buffer)
		_ = conn.Close()
		if err != nil || string(buffer[:n]) != message+"|"+own {
			t.Fatal("UDP server source does not prove selected path", source, string(buffer[:n]), own, err)
		}
	}
}
