package dataplane

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestResearchCanaryServicesRetainScopedRoutes(t *testing.T) {
	p := RoutePlan{Routes: []Route{
		{Resolved: "wireguard", ServiceName: "one", ProbeURL: "https://one.example/", Sources: []string{"192.168.1.4/32"}},
		{Resolved: "wireguard", ServiceName: "two", ProbeURL: "https://two.example/"},
		{Resolved: "xray", ServiceName: "foreign", ProbeURL: "https://foreign.example/"},
	}}
	before := append([]string(nil), p.Routes[0].Sources...)
	services := wireGuardCanaryServices(p, "wireguard")
	if len(services) != 2 || services[0].Name != "one" || !reflect.DeepEqual(before, p.Routes[0].Sources) {
		t.Fatal(services, p.Routes)
	}
}

func TestWGNewLiveInterfaceInitiatesColdScopedPeer(t *testing.T) {
	a, r, p, _ := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
	p.Routes[0].Sources = []string{"192.168.1.4/32"}
	if err := os.MkdirAll(filepath.Dir(a.RuntimeConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.RuntimeConfigPath, []byte(testOwnWireGuardProfile("")), 0o600); err != nil {
		t.Fatal(err)
	}
	var sent atomic.Bool
	a.Runner = &researchColdWGRunner{base: r, sent: &sent}
	a.HandshakeTimeout = time.Millisecond
	a.HealthProbe = func(ctx context.Context, url string) error {
		if device, _ := ctx.Value(wgSocketInterfaceKey{}).(string); device != a.Interface {
			t.Fatal("live probe not device-bound")
		}
		sent.Store(true)
		return nil
	}
	if err := a.probeLiveWGServices(context.Background(), p, ""); err != nil {
		t.Fatal(err)
	}
	if !sent.Load() || len(p.Routes[0].Sources) != 1 {
		t.Fatal("cold live peer did not initiate or lost scope")
	}
}

type researchColdWGRunner struct {
	base *warpFakeRunner
	sent *atomic.Bool
}

func (r *researchColdWGRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "wg" && len(args) == 3 && args[0] == "show" && args[2] == "latest-handshakes" {
		if r.sent.Load() {
			return []byte(fmt.Sprintf("peer\t%d\n", time.Now().Unix())), nil
		}
		return []byte("peer\t0\n"), nil
	}
	return r.base.Run(ctx, name, args...)
}

// Run under the real dataplane package in Codex. The native kernel/peer are
// replaced here, but the complete adapter Snapshot/Stage/Validate/Canary and
// cleanup paths are real. Physical-client proof is a separate HIL requirement.
func TestResearchWGColdPeerAndScopedOnlyPlan(t *testing.T) {
	profile := strings.ReplaceAll(testOwnWireGuardProfile(""), "PersistentKeepalive = 25\n", "")
	a, r, p, root := ownWireGuardFixture(t, profile)
	p.Routes[0].Sources = []string{"192.168.1.4/32"}
	var sent atomic.Bool
	a.NativeOnly = true
	a.Runner = &researchColdWGRunner{base: r, sent: &sent}
	a.HandshakeTimeout = time.Millisecond
	a.CanaryProbe = func(_ context.Context, url, source string) error {
		if url != "https://telegram.org/" || source != "10.66.0.2" {
			t.Fatalf("unscoped/wrong probe %s %s", url, source)
		}
		sent.Store(true)
		return nil
	}
	for _, f := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Validate} {
		if err := f(context.Background(), p, root); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Canary(context.Background(), p.RoutePlanFor("wireguard"), root); err != nil {
		t.Fatal(err)
	}
	if !sent.Load() {
		t.Fatal("cold peer never received traffic")
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "ip link delete dev rz-wg-canary") {
		t.Fatal("canary was not cleaned")
	}
}
