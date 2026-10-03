//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/tunnelcheck"
	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

// Called only by the opt-in TestWGNativeEndpointLifecycle child in its owned
// client namespace. Resolver/clock are explicit fixtures; WG, routes, socket
// mark, process restart and HTTP service evidence use the real kernel/runtime.
func nativeWGEndpointClient(t *testing.T) {
	base := os.Getenv("RAZVILKA_WG_NATIVE_ROOT")
	raw, err := os.ReadFile(filepath.Join(base, "client.conf"))
	if err != nil {
		t.Fatal(err)
	}
	endpoint := os.Getenv("RAZVILKA_WG_NATIVE_TEST_ENDPOINT")
	if endpoint != "93.184.216.34" && endpoint != "2606:4700::1111" {
		t.Fatal("explicit isolated endpoint fixture required")
	}
	for _, endpoint := range []string{endpoint} {
		t.Run(endpoint, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
			defer cancel()
			root := t.TempDir()
			store := wireguardprofile.New(filepath.Join(root, "profiles"))
			profile := strings.Replace(string(raw), "192.0.2.1:51820", "vpn.native.test:51820", 1)
			profile = strings.Replace(profile, "10.66.0.2/32, 2001:db8:66::2/128", "10.66.0.2/32", 1)
			metadata, err := store.Put(ctx, "native", "native fixture", profile, "")
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			answer := netip.MustParseAddr(endpoint)
			resolver := func(context.Context, string) ([]netip.Addr, time.Time, error) {
				return []netip.Addr{answer}, now.Add(time.Minute), nil
			}
			newAdapter := func() *WARPWireGuardAdapter {
				a := NewWireGuardAdapter(nil, root)
				a.WG, a.IP, a.Profiles = "wg", "ip", store
				a.EndpointResolver, a.EndpointNow = resolver, func() time.Time { return now }
				return a
			}
			a := newAdapter()
			captureProbeFailure := true
			t.Cleanup(func() {
				if t.Failed() {
					nativeWGKernelCapture(t, "", "endpoint child final state")
				}
			})
			a.CanaryProbe = func(probeCtx context.Context, url, source string) error {
				err := sourceBoundAWGProbe(probeCtx, url, source)
				if err != nil && captureProbeFailure {
					nativeWGKernelCapture(t, "", "candidate before production cleanup")
					if server := os.Getenv("RAZVILKA_WG_NATIVE_SERVER_NS"); server != "" {
						nativeWGKernelCapture(t, server, "server before candidate cleanup")
					}
				}
				return err
			}
			plan := Plan{Routes: []Route{{Resolved: "wireguard:native", ServiceName: "native", CIDRs: []string{"198.51.100.10/32"}, ProbeURL: "http://198.51.100.10/"}}}
			transaction := filepath.Join(root, "transaction")
			for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Validate} {
				if err := step(ctx, plan, transaction); err != nil {
					t.Fatal(err)
				}
			}
			// WAN is deliberately usable: prove the isolated bound canary cannot
			// borrow it when the WireGuard peer key is wrong.
			if err := sourceBoundAWGProbe(ctx, "http://198.51.100.10/", "192.0.2.2"); err != nil {
				t.Fatal("fixture WAN service control", err)
			}
			t.Log("ordinary WAN service control passed")
			staged := filepath.Join(transaction, "rz-warp.conf.staged")
			goodProfile, err := os.ReadFile(staged)
			if err != nil {
				t.Fatal(err)
			}
			_, wrongPublic := nativeWGKeys(t)
			lines := strings.Split(string(goodProfile), "\n")
			for i, line := range lines {
				if strings.HasPrefix(line, "PublicKey = ") {
					lines[i] = "PublicKey = " + wrongPublic
				}
			}
			if err := os.WriteFile(staged, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
				t.Fatal(err)
			}
			captureProbeFailure = false
			a.Timeout, a.HandshakeTimeout = 1200*time.Millisecond, 200*time.Millisecond
			if err := a.Canary(ctx, plan.RoutePlanFor(a.ID()), transaction); !errors.Is(err, tunnelcheck.ErrHandshake) {
				t.Fatal("wrong-key canary must fail with a handshake error despite reachable WAN", err)
			}
			t.Log("wrong-key canary rejected with handshake error while WAN service is reachable")
			a.Timeout, a.HandshakeTimeout = 25*time.Second, 8*time.Second
			captureProbeFailure = true
			if err := os.WriteFile(staged, goodProfile, 0o600); err != nil {
				t.Fatal(err)
			}
			candidate := *a
			candidate.Table, candidate.PriorityBase = 219, 18050
			if err := candidate.ensureCanaryPolicyFree(ctx); err != nil {
				t.Fatal("wrong-key canary leaked policy", err)
			}
			if _, err := exec.CommandContext(ctx, "ip", "link", "show", "rz-wg-canary").CombinedOutput(); err == nil {
				t.Fatal("wrong-key canary leaked interface")
			}
			if err := a.Canary(ctx, plan.RoutePlanFor(a.ID()), transaction); err != nil {
				t.Fatal("candidate", err)
			}
			t.Log("valid isolated candidate service and handshake passed")
			for _, step := range []func(context.Context, Plan, string) error{a.Activate, a.Health, a.Commit} {
				if err := step(ctx, plan, transaction); err != nil {
					t.Fatal(err)
				}
			}
			state, exists, err := a.loadPolicyState()
			if err != nil || !exists {
				t.Fatal("committed state", err)
			}
			e := state.WireGuardEndpoint
			if err := a.verifyWGEndpoint(ctx, e); err != nil {
				t.Fatal(err)
			}
			marked := nativeWGCommand(t, "", append([]string{"ip"}, e.args("-j", "route", "get", endpoint, "mark", "0x4000000")...)...)
			var routes []wgEndpointRoute
			err = json.Unmarshal([]byte(marked), &routes)
			if err != nil || len(routes) != 1 || routes[0].Destination != endpoint || routes[0].Device != e.Device || routes[0].Gateway != e.Gateway || routes[0].Source != e.Source || !wgEndpointTableMatches(routes[0].Table, e.Table) {
				t.Fatal("marked transport does not use the exact WAN pin", err, marked)
			}
			assertLive := func(label string) {
				if err := a.healthState(ctx, plan, state, ""); err != nil {
					t.Fatalf("live after %s: %v", label, err)
				}
			}
			// A fresh test process inherits only private files + kernel state.
			recoverProcess := func() {
				exe, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.CommandContext(ctx, exe, "-test.run=^TestWGNativeEndpointLifecycle$", "-test.v")
				cmd.Env = append(os.Environ(), "RAZVILKA_WG_NATIVE_ROLE=recover", "RAZVILKA_WG_NATIVE_RECOVER_ROOT="+root, "RAZVILKA_WG_NATIVE_ENDPOINT="+endpoint, "RAZVILKA_WG_NATIVE_NOW="+now.Format(time.RFC3339Nano))
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("new process recovery: %v\n%s", err, out)
				}
			}
			recoverProcess()
			a = newAdapter()
			// Both DNS expiry and WAN changes reject before removing the current pin.
			now = now.Add(2 * time.Minute)
			answer = netip.MustParseAddr("93.184.216.35")
			if err := a.Reconcile(ctx, plan); !errors.Is(err, ErrWGEndpointChanged) {
				t.Fatal("DNS change", err)
			}
			assertLive("rejected DNS change")
			answer = netip.MustParseAddr(endpoint)
			wanArgs := e.args("route", "replace", e.prefix(), "via", "192.0.2.5", "dev", "wan-b")
			if e.address().Is6() {
				nativeWGCommand(t, "", "ip", "address", "add", "2001:db8:2::2/64", "dev", "wan-b", "nodad")
				wanArgs = e.args("route", "replace", e.prefix(), "via", "2001:db8:2::1", "dev", "wan-b")
			}
			nativeWGCommand(t, "", append([]string{"ip"}, wanArgs...)...)
			if err := a.Reconcile(ctx, plan); !errors.Is(err, ErrWGEndpointChanged) {
				t.Fatal("WAN change", err)
			}
			assertLive("rejected WAN change")
			nativeWGCommand(t, "", append([]string{"ip"}, e.args("route", "replace", e.prefix(), "via", e.Gateway, "dev", e.Device)...)...)
			// Preserve unrelated owned-namespace resources through kernel recovery,
			// exact rollback and Stop. No table flush is allowed.
			foreign := "198.51.100.200/32"
			nativeWGCommand(t, "", "ip", "route", "add", foreign, "dev", "wan-b", "proto", "boot", "metric", "9", "table", "206")
			assertForeign := func() {
				out := nativeWGCommand(t, "", "ip", "route", "show", "table", "206", "exact", foreign)
				if !strings.Contains(out, "dev wan-b") || !strings.Contains(out, "metric 9") {
					t.Fatal("foreign host route lost", out)
				}
			}
			if err := removePolicy(ctx, a.Runner, a.ip(), state); err != nil {
				t.Fatal(err)
			}
			if err := a.stopInterface(ctx); err != nil {
				t.Fatal(err)
			}
			if err := a.removeWGEndpoint(ctx, e); err != nil {
				t.Fatal(err)
			}
			a = newAdapter()
			recoverProcess()
			assertLive("kernel state recovery")
			assertForeign()
			// The original transaction had no previous live runtime: rollback must
			// remove exactly this runtime and pin, preserving named profile + foreign.
			if err := a.Rollback(ctx, plan, transaction); err != nil {
				t.Fatal("rollback", err)
			}
			assertForeign()
			if route, rule, err := a.inspectWGEndpoint(ctx, e); err != nil || route || rule {
				t.Fatal("rollback leaked pin", err)
			}
			// Cold retry has a new snapshot and real live acceptance before Stop.
			transaction = filepath.Join(root, "retry")
			for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Validate} {
				if err := step(ctx, plan, transaction); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.Canary(ctx, plan.RoutePlanFor(a.ID()), transaction); err != nil {
				t.Fatal(err)
			}
			for _, step := range []func(context.Context, Plan, string) error{a.Activate, a.Health, a.Commit} {
				if err := step(ctx, plan, transaction); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.Deactivate(ctx); err != nil {
				t.Fatal("Stop", err)
			}
			assertForeign()
			if route, rule, err := a.inspectWGEndpoint(ctx, e); err != nil || route || rule {
				t.Fatal("Stop leaked pin", err)
			}
			if a.interfaceActive(ctx) {
				t.Fatal("Stop leaked interface")
			}
			p, err := store.Get(ctx, "native")
			if err != nil || p.Public().Revision != metadata.Revision || !strings.Contains(p.Config(), "vpn.native.test") {
				t.Fatal("lifecycle overwrote the original profile", err)
			}
			nativeWGCommand(t, "", "ip", "route", "del", foreign, "dev", "wan-b", "proto", "boot", "metric", "9", "table", "206")
		})
	}
}

// Diagnostic commands never read private-key, preshared-key, showconf or dump.
// Capture before production Canary's defer removes its temporary interface.
func nativeWGKernelCapture(t *testing.T, ns, label string) {
	t.Helper()
	captureCtx, cancelCapture := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCapture()
	commands := [][]string{
		{"ip", "-j", "-d", "link", "show"}, {"ip", "-j", "address", "show"},
		{"ip", "-4", "rule", "show"}, {"ip", "-6", "rule", "show"},
		{"ip", "-4", "-j", "route", "show", "table", "all"}, {"ip", "-6", "-j", "route", "show", "table", "all"},
		{"ip", "-4", "-j", "route", "get", "93.184.216.34", "mark", "0"},
		{"ip", "-6", "-j", "route", "get", "2606:4700::1111", "mark", "0"},
		{"ip", "-4", "-j", "route", "get", "198.51.100.10", "from", "10.66.0.2", "oif", "rz-wg-canary"},
		{"ip", "-4", "-j", "route", "get", "198.51.100.10", "from", "10.66.0.2"},
		{"sysctl", "-n", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter", "net.ipv4.conf.wan-c.rp_filter", "net.ipv4.conf.wan-s.rp_filter", "net.ipv4.conf.wg-server.rp_filter"},
	}
	for _, field := range []string{"public-key", "peers", "endpoints", "latest-handshakes", "transfer", "fwmark"} {
		commands = append(commands, []string{"wg", "show", "all", field})
		if tool := os.Getenv("RAZVILKA_AWG_NATIVE_TOOL"); tool != "" {
			commands = append(commands, []string{tool, "show", "all", field})
		}
	}
	for _, args := range commands {
		if captureCtx.Err() != nil {
			t.Logf("kernel capture %s: total diagnostic deadline reached", label)
			break
		}
		original := strings.Join(args, " ")
		if ns != "" {
			args = append([]string{"ip", "netns", "exec", ns}, args...)
		}
		ctx, cancel := context.WithTimeout(captureCtx, 2*time.Second)
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		cancel()
		if len(out) > 64<<10 {
			out = append(out[:64<<10], []byte("\n[bounded capture truncated]")...)
		}
		t.Logf("kernel capture %s | %s | err=%v\n%s", label, original, err, out)
	}
}

func nativeWGEndpointRecover(t *testing.T) {
	root := os.Getenv("RAZVILKA_WG_NATIVE_RECOVER_ROOT")
	addr, err := netip.ParseAddr(os.Getenv("RAZVILKA_WG_NATIVE_ENDPOINT"))
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, os.Getenv("RAZVILKA_WG_NATIVE_NOW"))
	if err != nil {
		t.Fatal(err)
	}
	a := NewWireGuardAdapter(nil, root)
	a.WG, a.IP = "wg", "ip"
	a.Profiles = wireguardprofile.New(filepath.Join(root, "profiles"))
	a.EndpointNow = func() time.Time { return now }
	a.EndpointResolver = func(context.Context, string) ([]netip.Addr, time.Time, error) {
		return []netip.Addr{addr}, now.Add(time.Minute), nil
	}
	plan := Plan{Routes: []Route{{Resolved: "wireguard:native", ServiceName: "native", CIDRs: []string{"198.51.100.10/32"}, ProbeURL: "http://198.51.100.10/"}}}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := a.Reconcile(ctx, plan); err != nil {
		t.Fatal(err)
	}
}
