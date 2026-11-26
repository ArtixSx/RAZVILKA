package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func proxyTestInterfaceInventory(a *ProxyTunnelAdapter) func() ([]net.Interface, error) {
	return func() ([]net.Interface, error) {
		links := []net.Interface{{Index: 1, Name: "lo"}}
		if a.Processes.Running(a.sidecarProcess()) {
			links = append(links, net.Interface{Index: 77, Name: a.Interface})
		}
		return links, nil
	}
}

func TestProxyDeactivateForwardingOnlyRetriesAfterLastLeaseIsConsumed(t *testing.T) {
	a, r, state := proxyForwardingFixture(t)
	a.Processes = r.processes
	ctx := context.Background()
	if err := a.installForwarding(ctx, state); err != nil {
		t.Fatal(err)
	}
	links := []net.Interface{{Index: 1, Name: "lo"}, {Index: 91, Name: a.Interface}}
	a.nodeInterfaceInventory = func() ([]net.Interface, error) { return links, nil }
	if err := a.Deactivate(ctx); !errors.Is(err, ErrProxyPolicyUnknown) || regularFile(a.forwardingPath()) {
		t.Fatal("partial teardown did not consume only its forwarding lease", err)
	}
	fresh, err := NewProxyTunnelAdapter(a.ID(), nil, filepath.Dir(a.StateRoot))
	if err != nil {
		t.Fatal(err)
	}
	fresh.nodeInterfaceInventory = a.nodeInterfaceInventory
	fresh.Processes, fresh.Runner = nil, nil // A pending readback cannot grant a network or process mutation.
	for _, step := range []func(context.Context, Plan, string) error{fresh.Snapshot, fresh.Stage, fresh.Activate} {
		if err := step(ctx, Plan{}, t.TempDir()); !errors.Is(err, ErrProxyPolicyUnknown) {
			t.Fatal("incomplete Stop admitted a new operation", err)
		}
	}
	if err := fresh.inactiveFiles(ctx); !errors.Is(err, ErrProxyRuntimeInactive) {
		t.Fatal("pending cleanup reported inactive files", err)
	}
	if err := fresh.Deactivate(ctx); !errors.Is(err, ErrProxyPolicyUnknown) {
		t.Fatal("incomplete Stop lost its pending interface check", err)
	}
	links = links[:1]
	if err := fresh.Deactivate(ctx); err != nil || regularFile(filepath.Join(a.StateRoot, proxyPartialStopFile)) {
		t.Fatal("confirmed release did not close the partial Stop", err)
	}
}

func TestProxyDeactivateColdDispatchFinishesOnlyPendingReadback(t *testing.T) {
	f := newXrayDispatchFixture(t)
	a := f.a
	ctx := context.Background()
	if err := os.MkdirAll(a.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := a.partialStopInterface(ctx, partialStopBegin); err != nil {
		t.Fatal(err)
	}
	links := []net.Interface{{Index: 1, Name: "lo"}, {Index: 91, Name: a.Interface}}
	a.nodeInterfaceInventory = func() ([]net.Interface, error) { return links, nil }
	retiring := Plan{RetiringAdapters: []string{a.ID()}}
	if err := a.Snapshot(ctx, retiring, t.TempDir()); !errors.Is(err, ErrProxyPolicyUnknown) {
		t.Fatal("retirement with unresolved TUN entered a snapshot", err)
	}
	if err := a.Deactivate(ctx); !errors.Is(err, ErrProxyPolicyUnknown) {
		t.Fatal("cold dispatcher lost pending cleanup", err)
	}
	links = links[:1]
	if err := a.Snapshot(f.ctx, retiring, privateScopedXrayFixtureDir(t)); err != nil || !regularFile(filepath.Join(a.StateRoot, proxyPartialStopFile)) {
		t.Fatal("retiring snapshot must retain verified pending Stop for Deactivate", err)
	}
	a.Processes, a.Runner = nil, nil
	if err := a.Deactivate(ctx); err != nil || regularFile(filepath.Join(a.StateRoot, proxyPartialStopFile)) {
		t.Fatal("cold dispatcher failed to finish readback", err)
	}
}

func TestProxyDeactivateRetainsPolicyFileUntilInterfaceIsReleased(t *testing.T) {
	a, r, state := proxyForwardingFixture(t)
	a.Processes = r.processes
	ctx := context.Background()
	if err := a.applyOwnedPolicy(ctx, state); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.policyPath(), raw, 0600); err != nil {
		t.Fatal(err)
	}
	links := []net.Interface{{Index: 1, Name: "lo"}, {Index: 91, Name: a.Interface}}
	a.nodeInterfaceInventory = func() ([]net.Interface, error) { return links, nil }
	for range 2 {
		if err := a.Deactivate(ctx); !errors.Is(err, ErrProxyPolicyUnknown) {
			t.Fatal("policy-only Stop lost unresolved TUN", err)
		}
		if data, err := os.ReadFile(a.policyPath()); err != nil || string(data) != string(raw) {
			t.Fatal("policy file was consumed before interface release", err)
		}
	}
	links = links[:1]
	if err := a.Deactivate(ctx); err != nil || regularFile(a.policyPath()) {
		t.Fatal("policy-only Stop did not finish", err)
	}
}

func TestProxyDeactivateRejectsChangedPartialStopDuringObservation(t *testing.T) {
	a, err := NewProxyTunnelAdapter("sing-box", nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := os.MkdirAll(a.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := a.partialStopInterface(ctx, partialStopBegin); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(a.StateRoot, proxyPartialStopFile)
	a.Processes, a.Runner = nil, nil
	a.nodeInterfaceInventory = func() ([]net.Interface, error) {
		if err := os.WriteFile(path, []byte("different operation\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return []net.Interface{{Index: 1, Name: "lo"}}, nil
	}
	if err := a.Deactivate(ctx); !errors.Is(err, ErrProxyPolicyUnknown) || !regularFile(path) {
		t.Fatal("readback removed another operation's record", err)
	}
}

func TestProxyDeactivateRetainsUnconfirmedTunnelAndRetryFiles(t *testing.T) {
	for _, failure := range []string{"process-stop", "same-name-replacement", "inventory-failed"} {
		t.Run(failure, func(t *testing.T) {
			a, err := NewProxyTunnelAdapter("xray", nil, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			a.IP = "ip"
			if err := os.MkdirAll(a.runtimeRoot(), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(a.engineConfigPath(), []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			processes := &proxyFakeProcesses{running: map[string]bool{}}
			a.Processes = processes
			if failure == "process-stop" {
				a.Processes = &unstagedFailingStop{ProcessController: processes, err: errors.New("child not joined")}
			}
			linkPresent := failure != "inventory-failed"
			a.nodeInterfaceInventory = func() ([]net.Interface, error) {
				if failure == "process-stop" {
					t.Fatal("checked interface before confirming child shutdown")
				}
				if failure == "inventory-failed" {
					return nil, errors.New("inventory interrupted")
				}
				links := []net.Interface{{Index: 1, Name: "lo"}}
				if linkPresent {
					links = append(links, net.Interface{Index: 91, Name: a.Interface})
				}
				return links, nil
			}
			deleted := false
			a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				switch strings.Join(args, " ") {
				case "link show dev " + a.Interface:
					if linkPresent {
						return []byte("91: " + a.Interface), nil
					}
					return nil, errors.New("inventory interrupted")
				case "link delete dev " + a.Interface:
					deleted = true
					return nil, nil
				default:
					return nil, errors.New("unexpected command")
				}
			})
			err = a.Deactivate(context.Background())
			if err == nil || deleted || !regularFile(a.engineConfigPath()) {
				t.Fatalf("Stop lost partial state: err=%v linkDeleted=%v configRetained=%v", err, deleted, regularFile(a.engineConfigPath()))
			}
			a.Processes = processes
			linkPresent = false
			a.nodeInterfaceInventory = proxyTestInterfaceInventory(a)
			if err := a.Deactivate(context.Background()); err != nil || deleted || regularFile(a.engineConfigPath()) {
				t.Fatalf("retry after verified disappearance: err=%v linkDeleted=%v", err, deleted)
			}
		})
	}
}

func TestScopedProxyDeactivateDoesNotDeleteByNameAfterLastLeaseRead(t *testing.T) {
	f := scopedXrayTestFixture(t)
	a, ctx := f.a, context.Background()
	root := stageScopedFixture(t, f)
	for _, step := range []func(context.Context, Plan, string) error{a.Activate, a.Health, a.Commit} {
		if err := step(ctx, f.plan, root); err != nil {
			t.Fatal(err)
		}
	}
	base := a.Runner
	visible, deletedReplacement := true, false
	a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		// After Stop the old device is briefly visible under its recorded index.
		// A same-name replacement wins the race before a name-based delete.
		if name == "ip" && !f.processes.running["xray-tun"] && visible {
			switch strings.Join(args, " ") {
			case "-j link show dev " + a.Interface:
				return []byte(`[{"ifindex":77,"ifname":"` + a.Interface + `"}]`), nil
			case "link delete dev " + a.Interface:
				deletedReplacement, visible = true, false
				return nil, nil
			}
		}
		return base.Run(ctx, name, args...)
	})
	if err := a.Deactivate(ctx); err == nil || deletedReplacement || !regularFile(a.nodeInterfacePath()) {
		t.Fatalf("residual interface: err=%v replacementDeleted=%v leaseRetained=%v", err, deletedReplacement, regularFile(a.nodeInterfacePath()))
	}
	visible = false
	if err := a.Deactivate(ctx); err != nil || regularFile(a.nodeInterfacePath()) {
		t.Fatalf("retry after confirmed release: err=%v", err)
	}
}
