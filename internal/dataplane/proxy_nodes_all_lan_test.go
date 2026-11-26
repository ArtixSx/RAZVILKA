package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Exercise the real exact-node Stage with all-LAN intent, retaining the
// existing physical bridge readback. No 0/0 source or foreign VPN is admitted.
func TestScopedXrayAllLANStageUsesOnlyObservedBridgePrefixes(t *testing.T) {
	f := scopedXrayTestFixture(t)
	f.a.nodeRouterVerifier, f.a.NodeTUNProbe = true, nil
	f.plan.Routes[0].Sources = nil
	service := nodeRouterFixtureCatalog(f.plan.Routes[0].ProbeURL)
	service.ID = f.plan.Routes[0].ServiceID
	f.plan.Routes[0].ProbeService = &service
	l := newProxyLANFixture(t)
	l.a.Interface = f.a.Interface
	base := f.a.Runner
	f.a.LANBridgeMembers = l.a.LANBridgeMembers
	f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		if name == "ip" && (strings.HasPrefix(command, "route show table main") || strings.HasPrefix(command, "-6 route show table main") || strings.HasPrefix(command, "addr show dev ") || strings.HasPrefix(command, "-6 addr show dev ") || strings.HasPrefix(command, "route get 192.168.") || strings.HasPrefix(command, "route get 172.16.")) {
			return l.a.Runner.Run(ctx, name, args...)
		}
		return base.Run(ctx, name, args...)
	})
	root := privateScopedXrayFixtureDir(t)
	ctx := context.Background()
	if err := f.a.Snapshot(ctx, f.plan, root); err != nil {
		t.Fatal(err)
	}
	if err := f.a.Stage(ctx, f.plan, root); err != nil {
		t.Fatal(err)
	}
	state, err := f.a.readStagedPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, rule := range state.Rules {
		if rule.Destination != "8.8.8.8/32" {
			t.Fatal("destination widened", rule)
		}
		got[rule.Source] = true
	}
	if !reflect.DeepEqual(got, map[string]bool{"172.16.1.0/24": true, "192.168.1.0/24": true}) {
		t.Fatal("unproven source admitted", got)
	}
	if state.Forwarding == nil || len(state.Forwarding.Rules) != 2 {
		t.Fatal("bridge forwarding not recorded", state.Forwarding)
	}
	manifest, err := f.a.readNodeManifest(filepath.Join(root, "nodes.staged.json"))
	if err != nil || len(manifest.Routes) != 1 || len(manifest.Routes[0].Sources) != 0 {
		t.Fatal("owner all-LAN intent changed", err)
	}
	if len(f.plan.Routes[0].Sources) != 0 {
		t.Fatal("Stage changed frozen intent")
	}
	// A freshly constructed dispatcher must be able to read the same saved
	// all-LAN manifest. Old selected/control-only consumers still refuse it.
	raw, err := os.ReadFile(filepath.Join(root, "nodes.staged.json"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := os.ReadFile(filepath.Join(root, "engine.staged.json"))
	if err != nil {
		t.Fatal(err)
	}
	sidecar, err := os.ReadFile(filepath.Join(root, "sidecar.staged.json"))
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := NewXrayRuntimeAdapter(f.a.Configs, filepath.Dir(f.a.StateRoot), f.a.NodeRoutes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.validateXrayModeManifest(raw, engine, sidecar); err != nil {
		t.Fatal("fresh dispatcher rejected all-LAN", err)
	}
	fresh.nodeRouterVerifier = false
	if _, err := fresh.validateXrayModeManifest(raw, engine, sidecar); err == nil {
		t.Fatal("external-only verifier accepted empty client scope")
	}
}

func TestScopedXrayAllLANRefusesUnprovenScopeBeforeStagedFiles(t *testing.T) {
	for _, mode := range []string{"external-only", "missing-bridge"} {
		t.Run(mode, func(t *testing.T) {
			f := scopedXrayTestFixture(t)
			f.plan.Routes[0].Sources = nil
			if mode == "missing-bridge" {
				f.a.nodeRouterVerifier, f.a.NodeTUNProbe = true, nil
				service := nodeRouterFixtureCatalog(f.plan.Routes[0].ProbeURL)
				service.ID = f.plan.Routes[0].ServiceID
				f.plan.Routes[0].ProbeService = &service
				f.a.LANBridgeMembers = func(context.Context, string) ([]string, error) { return nil, nil }
			}
			root := privateScopedXrayFixtureDir(t)
			if err := f.a.Snapshot(context.Background(), f.plan, root); err != nil {
				t.Fatal(err)
			}
			err := f.a.Stage(context.Background(), f.plan, root)
			if err == nil {
				t.Fatal("unproven all-LAN accepted")
			}
			var refused preflightRefusalError
			if mode == "missing-bridge" && !errors.As(err, &refused) {
				t.Fatal("did not reach physical scope preflight", err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 1 || entries[0].Name() != "snapshot.json" {
				t.Fatal("refusal left candidate effects", entries, err)
			}
			if len(f.processes.running) != 0 {
				t.Fatal("refusal started a runtime")
			}
		})
	}
}
