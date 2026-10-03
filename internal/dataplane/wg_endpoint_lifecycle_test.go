package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func wgEndpointFixture(t *testing.T) (*WARPWireGuardAdapter, *warpFakeRunner, *WGEndpointState, string) {
	t.Helper()
	a, r, plan, root := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
	if err := a.Snapshot(context.Background(), plan, root); err != nil {
		t.Fatal(err)
	}
	if err := a.Stage(context.Background(), plan, root); err != nil {
		t.Fatal(err)
	}
	state, err := a.readStagedPolicy(root)
	if err != nil || state.WireGuardEndpoint == nil {
		t.Fatal(state, err)
	}
	return a, r, state.WireGuardEndpoint, root
}

type wgEndpointRouteJSONRunner struct {
	*warpFakeRunner
	response []byte
}

func (r *wgEndpointRouteJSONRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "ip" && strings.HasPrefix(strings.Join(args, " "), "-6 -j route get ") {
		return r.response, nil
	}
	return r.warpFakeRunner.Run(ctx, name, args...)
}

// The independent native-wg-06 capture contains from:"::" in a unique
// iproute2 IPv6 route-get result. It is a source selector, not prefsrc.
func TestWGEndpointCapturedIPv6RouteGet(t *testing.T) {
	a, r, plan, root := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
	a.Runner = &wgEndpointRouteJSONRunner{warpFakeRunner: r, response: []byte(`[{"dst":"2606:4700::1111","from":"::","gateway":"2001:db8:1::1","dev":"wan-c","prefsrc":"2001:db8:1::2","metric":1024,"flags":[],"pref":"medium"}]`)}
	a.EndpointResolver = func(context.Context, string) ([]netip.Addr, time.Time, error) {
		return []netip.Addr{netip.MustParseAddr("2606:4700::1111")}, time.Now().Add(time.Minute), nil
	}
	ctx := context.Background()
	if err := a.Snapshot(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	if err := a.Stage(ctx, plan, root); err != nil {
		t.Fatal("captured unique IPv6 route rejected", err)
	}
	state, err := a.readStagedPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	e := state.WireGuardEndpoint
	if e.Endpoint != "[2606:4700::1111]:51820" || e.Source != "2001:db8:1::2" || e.Gateway != "2001:db8:1::1" || e.Device != "wan-c" {
		t.Fatal("source selector replaced the selected WAN source", e)
	}
}

func TestWGEndpointRouteSourceSelector(t *testing.T) {
	for _, tc := range []struct {
		name, dst, from string
		valid           bool
	}{
		{"IPv6 unspecified", "2606:4700::1111", `"::"`, true},
		{"IPv6 zero prefix", "2606:4700::1111/128", `"::/0"`, true},
		{"IPv4 unspecified", "93.184.216.34", `"0.0.0.0"`, true},
		{"IPv4 zero prefix", "93.184.216.34/32", `"0.0.0.0/0"`, true},
		{"IPv6 host", "2606:4700::1111", `"2001:db8:1::2"`, false},
		{"IPv6 host prefix", "2606:4700::1111", `"2001:db8:1::2/128"`, false},
		{"IPv6 network prefix", "2606:4700::1111", `"2001:db8:1::/64"`, false},
		{"unspecified restricted prefix", "2606:4700::1111", `"::/128"`, false},
		{"nonzero zero prefix", "2606:4700::1111", `"::1/0"`, false},
		{"wrong family", "2606:4700::1111", `"0.0.0.0"`, false},
		{"wrong family IPv4", "93.184.216.34", `"::"`, false},
		{"zone", "2606:4700::1111", `"::%wan-c"`, false},
		{"empty", "2606:4700::1111", `""`, false},
		{"null", "2606:4700::1111", `null`, false},
		{"number", "2606:4700::1111", `0`, false},
		{"malformed", "2606:4700::1111", `"unknown"`, false},
		{"missing destination", "", `"::"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseWGEndpointRoutes([]byte(`[{"dst":"` + tc.dst + `","from":` + tc.from + `,"dev":"wan-c"}]`))
			if (err == nil) != tc.valid {
				t.Fatal("source selector acceptance", err)
			}
		})
	}
	if _, err := parseWGEndpointRoutes([]byte(`[{"dst":"2606:4700::1111","from":"::","unsupported":true}]`)); err == nil {
		t.Fatal("unknown attribute accepted")
	}
}

func TestWGEndpointExactPinInstallReadbackAndCleanup(t *testing.T) {
	a, r, e, _ := wgEndpointFixture(t)
	ctx := context.Background()
	if e.Mark != 0x04000000 || e.Priority != 52 || e.Table != 206 || e.Original != "vpn.example.com:51820" {
		t.Fatal(e)
	}
	if err := a.installWGEndpoint(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := a.installWGEndpoint(ctx, e); err == nil {
		t.Fatal("occupied pin adopted")
	}
	// An unrelated route in the same table never becomes cleanup authority.
	r.endpoint.routes["4|203.0.113.9/32"] = wgEndpointRoute{Destination: "203.0.113.9/32", Device: "foreign", Metric: 9}
	if err := a.removeWGEndpoint(ctx, e); err != nil {
		t.Fatal(err)
	}
	if len(r.endpoint.routes) != 1 || r.endpoint.routes["4|203.0.113.9/32"].Device != "foreign" {
		t.Fatal("foreign route deleted")
	}
	for _, call := range r.calls {
		if strings.Contains(call, "flush") {
			t.Fatal("global cleanup", call)
		}
	}
}

func TestWGEndpointForeignNearMatchStopsBeforeMutation(t *testing.T) {
	for _, kind := range []string{"mark", "metric", "gateway", "source selector"} {
		t.Run(kind, func(t *testing.T) {
			a, r, e, _ := wgEndpointFixture(t)
			ctx := context.Background()
			if err := a.installWGEndpoint(ctx, e); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "mark":
				r.endpoint.rules["4|52"] = strings.Replace(r.endpoint.rules["4|52"], "0x4000000/0xffffffff", "0x4000000/0xff000000", 1)
			case "metric":
				v := r.endpoint.routes["4|"+e.prefix()]
				v.Metric = 2
				r.endpoint.routes["4|"+e.prefix()] = v
			case "gateway":
				v := r.endpoint.routes["4|"+e.prefix()]
				v.Gateway = "192.0.2.9"
				r.endpoint.routes["4|"+e.prefix()] = v
			case "source selector":
				v := r.endpoint.routes["4|"+e.prefix()]
				v.From = "192.0.2.2/32"
				r.endpoint.routes["4|"+e.prefix()] = v
			}
			r.calls = nil
			if err := a.removeWGEndpoint(ctx, e); err == nil {
				t.Fatal("foreign near-match accepted")
			}
			for _, call := range r.calls {
				if strings.Contains(call, " del ") {
					t.Fatal("mutated after ownership failed", call)
				}
			}
		})
	}
}

func TestWGEndpointDNSExpiryAndWANChangeRequireRevalidation(t *testing.T) {
	a, r, e, _ := wgEndpointFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	a.EndpointNow = func() time.Time { return now }
	lookups := 0
	a.EndpointResolver = func(context.Context, string) ([]netip.Addr, time.Time, error) {
		lookups++
		return []netip.Addr{e.address()}, now.Add(time.Minute), nil
	}
	// Address-only fallback has no fabricated TTL and must re-resolve at start.
	if !e.ExpiresAt.IsZero() {
		t.Fatal("invented TTL")
	}
	if err := a.revalidateWGEndpoint(ctx, e); err != nil || lookups != 1 {
		t.Fatal(err, lookups)
	}
	if err := a.revalidateWGEndpoint(ctx, e); err != nil || lookups != 1 {
		t.Fatal("fresh TTL ignored", err, lookups)
	}
	now = now.Add(time.Minute)
	a.EndpointResolver = func(context.Context, string) ([]netip.Addr, time.Time, error) {
		lookups++
		return []netip.Addr{netip.MustParseAddr("93.184.216.35")}, now.Add(time.Minute), nil
	}
	if err := a.revalidateWGEndpoint(ctx, e); !errors.Is(err, ErrWGEndpointChanged) {
		t.Fatal("expired changed endpoint accepted", err)
	}
	if e.Endpoint != "93.184.216.34:51820" {
		t.Fatal("endpoint mutated without candidate")
	}
	a.EndpointResolver = func(context.Context, string) ([]netip.Addr, time.Time, error) {
		return []netip.Addr{e.address()}, now.Add(time.Minute), nil
	}
	r.endpoint.wanDevice = "eth1"
	if err := a.revalidateWGEndpoint(ctx, e); !errors.Is(err, ErrWGEndpointChanged) {
		t.Fatal("changed WAN accepted", err)
	}
	if e.Device != "eth0" {
		t.Fatal("WAN pin silently changed")
	}
}

func TestWGEndpointActivationCommitStopAndRollbackOwnership(t *testing.T) {
	a, r, plan, root := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
	ctx := context.Background()
	if err := a.Snapshot(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readWarpWGSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.ProfilePath = filepath.Join(t.TempDir(), "client.conf")
	data, _ := json.Marshal(snapshot)
	if err := os.WriteFile(filepath.Join(root, "snapshot.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Stage(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	if err := a.Activate(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	state, err := a.readStagedPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.verifyWGEndpoint(ctx, state.WireGuardEndpoint); err != nil {
		t.Fatal(err)
	}
	if err := a.Commit(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	if _, owned, err := a.deactivationOwnership(ctx); err != nil || !owned {
		t.Fatal("commit did not bind pin ownership", err)
	}
	manager := New(t.TempDir())
	if err := manager.Register(a); err != nil {
		t.Fatal(err)
	}
	rule := r.endpoint.rules["4|52"]
	if !manager.OwnsPolicyRule("wireguard", 4, rule) || manager.OwnsPolicyRule("wireguard", 4, strings.Replace(rule, "0xffffffff", "0xff000000", 1)) {
		t.Fatal("endpoint rule ownership is not exact")
	}
	route := "93.184.216.34 via 192.0.2.1 dev eth0 proto static src 192.0.2.2 metric 1 onlink"
	if !manager.OwnsPolicyRoute("wireguard", 4, route) || manager.OwnsPolicyRoute("wireguard", 4, route+" linkdown") {
		t.Fatal("endpoint route ownership is not exact")
	}
	public := r.endpoint.publicKey
	r.endpoint.publicKey = "foreign"
	r.calls = nil
	if err := a.Deactivate(ctx); err == nil {
		t.Fatal("foreign interface accepted")
	}
	for _, call := range r.calls {
		if strings.Contains(call, " del ") || strings.Contains(call, "link delete") {
			t.Fatal("foreign identity mutated", call)
		}
	}
	r.endpoint.publicKey = public
	// Expired/noncacheable changed DNS preserves the current LKG untouched.
	a.EndpointResolver = func(context.Context, string) ([]netip.Addr, time.Time, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.35")}, time.Time{}, nil
	}
	r.calls = nil
	if err := a.Reconcile(ctx, plan); !errors.Is(err, ErrWGEndpointChanged) {
		t.Fatal(err)
	}
	for _, call := range r.calls {
		if strings.Contains(call, " del ") || strings.Contains(call, "link delete") {
			t.Fatal("DNS change destroyed LKG", call)
		}
	}
	a.EndpointResolver = nil
	// Reboot loses only kernel state; recover from the private committed tuple.
	r.active = false
	r.policy.entries = nil
	r.endpoint = wgEndpointKernelFake{}
	r.routeDevice = a.Interface
	a.HealthProbe = func(context.Context, string) error { return nil }
	if err := a.Reconcile(ctx, plan); err != nil {
		t.Fatal("committed recovery: ", err)
	}
	if err := a.Deactivate(ctx); err != nil {
		t.Fatal(err)
	}
	if r.active || len(r.endpoint.routes) != 0 || len(r.endpoint.rules) != 0 {
		t.Fatal("Stop left owned resources")
	}
	if data, err := os.ReadFile(snapshot.ProfilePath); err != nil || !strings.Contains(string(data), "vpn.example.com") {
		t.Fatal("Stop or pin overwrote original hostname", err)
	}
}

func TestWGEndpointIPv6TransportPin(t *testing.T) {
	a, r, plan, root := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
	ctx := context.Background()
	a.EndpointResolver = func(context.Context, string) ([]netip.Addr, time.Time, error) {
		return []netip.Addr{netip.MustParseAddr("2606:4700::1111")}, time.Now().Add(time.Minute), nil
	}
	if err := a.Snapshot(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	if err := a.Stage(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	state, err := a.readStagedPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	e := state.WireGuardEndpoint
	if err := a.installWGEndpoint(ctx, e); err != nil {
		t.Fatal(err)
	}
	if !e.matchesRule(6, r.endpoint.rules["6|52"]) || e.matchesRule(4, r.endpoint.rules["6|52"]) {
		t.Fatal("IPv6 pin identity")
	}
	if err := a.removeWGEndpoint(ctx, e); err != nil {
		t.Fatal(err)
	}
}

func TestWGEndpointRollbackAfterForeignInterfaceCollisionKeepsForeignLink(t *testing.T) {
	a, r, plan, root := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
	ctx := context.Background()
	if err := a.Snapshot(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	if err := a.Stage(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	r.failStart = true
	if err := a.Activate(ctx, plan, root); err == nil {
		t.Fatal("creation collision accepted")
	}
	r.calls = nil
	if err := a.Rollback(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	if !r.active {
		t.Fatal("foreign link removed during rollback")
	}
	for _, call := range r.calls {
		if strings.Contains(call, "link delete") {
			t.Fatal("foreign link delete", call)
		}
	}
	if len(r.endpoint.routes) != 0 || len(r.endpoint.rules) != 0 {
		t.Fatal("owned pin was not cleaned")
	}
}
