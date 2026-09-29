package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// upgradeFixture activates a committed NFQWS2 plan, then reproduces the
// installer: controlled deactivation (managed blocks removed, lease deleted)
// followed by restoring the journal and the lease from the update snapshot.
func upgradeFixture(t *testing.T) (*NFQWS2Adapter, *nfqwsFakeRunner, Plan, [][]byte) {
	t.Helper()
	a, runner, root := newOwnedNFQWS2(t)
	a.IPTablesSave = "iptables-save"
	transaction := stageOwnedNFQWS2(t, a, root, "service.example")
	plan := Plan{Routes: []Route{{Resolved: "nfqws2", Domains: []string{"service.example"}, CIDRs: []string{"203.0.113.0/24"}}}}
	if err := a.Activate(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	applied := readNFQWS2Files(t, a)
	lease, err := os.ReadFile(filepath.Join(a.StateRoot, nfqws2LeaseFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(a.UserListPath); strings.Contains(string(data), managedBegin) {
		t.Fatal("fixture deactivation kept the managed block")
	}
	if err := os.WriteFile(filepath.Join(a.StateRoot, nfqws2LeaseFile), lease, 0o600); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	return a, runner, plan, applied
}

// Regression for the 0.19.0 installation on the owner's router: boot recovery
// found no managed block after the installer's deactivation, entered Recovery
// Safe Mode, and the update rolled back ("no current runtime evidence").
func TestNFQWS2ReconcileRestoresBlocksRemovedByControlledDeactivation(t *testing.T) {
	a, runner, plan, applied := upgradeFixture(t)
	if err := a.Reconcile(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	for index, data := range readNFQWS2Files(t, a) {
		if string(data) != string(applied[index]) {
			t.Fatalf("resource %d not restored to the applied state:\n%s", index, data)
		}
	}
	if !slices.ContainsFunc(runner.calls, func(call string) bool { return strings.HasSuffix(call, " restart") }) {
		t.Fatalf("NFQWS2 not restarted with the restored lists: %v", runner.calls)
	}
}

// Only the block the lease recorded may come back: another plan, or a changed
// configuration, keeps recovery refused and the shared files untouched.
func TestNFQWS2ReconcileRefusesUnprovenBlocks(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, a *NFQWS2Adapter, plan *Plan){
		"different plan": func(t *testing.T, a *NFQWS2Adapter, plan *Plan) {
			plan.Routes[0].Domains = []string{"other.example"}
		},
		"changed configuration": func(t *testing.T, a *NFQWS2Adapter, plan *Plan) {
			if err := os.WriteFile(a.ConfigPath, []byte("ISP_INTERFACE=eth9\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, _, plan, _ := upgradeFixture(t)
			change(t, a, &plan)
			before := readNFQWS2Files(t, a)
			if err := a.Reconcile(context.Background(), plan); err == nil {
				t.Fatal("unproven managed block restored")
			}
			assertNFQWS2Files(t, a, before)
		})
	}
}
