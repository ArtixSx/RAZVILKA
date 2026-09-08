package dataplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxyRollbackRestoresOnlySameBootActivePolicy(t *testing.T) {
	for _, tc := range []struct {
		name                                string
		live, reboot, legacy, missingKernel bool
		wantPolicy                          bool
	}{
		{"live-A-failed-B", true, false, false, false, true},
		{"cold-history-failed-B", false, false, false, false, false},
		{"journal-survived-reboot", true, true, false, false, false},
		{"legacy-journal-no-boot-proof", true, false, true, false, false},
		{"running-pair-without-policy-lease", true, false, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r, old := proxyForwardingFixture(t)
			ctx := context.Background()
			boot := "boot-A"
			a.bootIdentity = func() (string, error) { return boot, nil }
			a.Processes = r.processes
			a.EngineBin = "sing-box"
			a.SidecarBin = "sing-box"
			if err := os.MkdirAll(a.runtimeRoot(), 0o700); err != nil {
				t.Fatal(err)
			}
			oldData, _ := json.Marshal(old)
			for path, data := range map[string][]byte{a.policyPath(): oldData, a.engineConfigPath(): []byte(`{}`), a.sidecarConfigPath(): []byte(`{}`)} {
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.live {
				r.processes.running["sing-box-engine"] = true
				r.processes.running["sing-box-tun"] = true
				if err := a.installForwarding(ctx, old); err != nil {
					t.Fatal(err)
				}
				if tc.missingKernel {
					if err := a.removeForwarding(ctx); err != nil {
						t.Fatal(err)
					}
				}
			}
			transaction := t.TempDir()
			if err := a.Snapshot(ctx, Plan{}, transaction); err != nil {
				t.Fatal(err)
			}
			snapshot, err := readProxySnapshot(transaction)
			if err != nil {
				t.Fatal(err)
			}
			if !snapshot.PolicyExists || snapshot.PolicyWasActive != (tc.live && !tc.missingKernel) {
				t.Fatalf("snapshot promoted history: %+v", snapshot)
			}
			if err := a.removeForwarding(ctx); err != nil {
				t.Fatal(err)
			}
			// B has installed its own temporary grants before a forced failure.
			desired := old
			desired.Prefixes = []string{"198.51.100.21/32"}
			desired.Rules = []PolicyRule{{Source: "192.168.1.25/32", Destination: desired.Prefixes[0]}}
			desired.Forwarding, err = a.compileForwarding(ctx, desired)
			if err != nil {
				t.Fatal(err)
			}
			if err := a.installForwarding(ctx, desired); err != nil {
				t.Fatal(err)
			}
			staged, _ := json.Marshal(desired)
			if err := os.WriteFile(filepath.Join(transaction, "policy.staged.json"), staged, 0o600); err != nil {
				t.Fatal(err)
			}
			r.processes.running["sing-box-engine"] = true
			r.processes.running["sing-box-tun"] = true
			if tc.reboot {
				boot = "boot-B"
			}
			if tc.legacy {
				snapshot.BootID = ""
				snapshot.PolicyWasActive = false
				data, _ := json.Marshal(snapshot)
				if err := os.WriteFile(filepath.Join(transaction, "snapshot.json"), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			addedRules := 0
			base := a.Runner
			a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == "ip" && strings.Contains(strings.Join(args, " "), "rule add") {
					addedRules++
				}
				return base.Run(ctx, name, args...)
			})
			if err := a.Rollback(ctx, Plan{}, transaction); err != nil {
				t.Fatal(err)
			}
			if (addedRules > 0) != tc.wantPolicy || regularFile(a.forwardingPath()) != tc.wantPolicy {
				t.Fatalf("rollback authority mismatch: adds=%d manifest=%t", addedRules, regularFile(a.forwardingPath()))
			}
			if tc.wantPolicy {
				if err := a.verifyForwarding(ctx, old); err != nil {
					t.Fatalf("live A not restored: %v", err)
				}
			}
			if (!tc.live || tc.reboot || tc.legacy) && len(r.processes.running) != 0 {
				t.Fatalf("cold/old-boot journal restarted processes: %v", r.processes.running)
			}
			retained, exists, err := a.loadPolicy()
			if err != nil || !exists || !samePolicy(retained, old) {
				t.Fatalf("rollback lost historical policy: %+v %v", retained, err)
			}
		})
	}
}
