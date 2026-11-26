package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func coldRollbackAbsenceFixture(t *testing.T) (*inactiveFixture, string, PolicyState) {
	t.Helper()
	f := newInactiveFixture(t, "sing-box")
	if err := os.MkdirAll(f.a.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	root := privateScopedXrayFixtureDir(t)
	snapshot := proxySnapshot{EngineID: f.a.ID(), SidecarKind: f.a.effectiveSidecar(), ConfigPath: filepath.Join(root, "package.json"), BootID: "inactive-fixture-boot"}
	raw, _ := json.Marshal(snapshot)
	inactiveWrite(t, filepath.Join(root, "snapshot.json"), raw)
	state := PolicyState{Interface: f.a.Interface, Table: f.a.Table, PriorityBase: f.a.Priority, Prefixes: []string{"198.51.100.20/32"},
		Forwarding: &ProxyForwardingState{Chain: f.a.forwardingChain(), Rules: []ProxyForwardingRule{{Source: "192.168.1.25/32", Destination: "198.51.100.20/32", Ingress: "br0"}}}}
	initializePolicyLayout(&state)
	raw, _ = json.Marshal(state)
	inactiveWrite(t, filepath.Join(root, "policy.staged.json"), raw)
	steps, err := policyAdditionExpected(state)
	if err != nil {
		t.Fatal(err)
	}
	for i := range steps {
		steps[i].State = "removed"
	}
	doc := policyAdditionDocument{Schema: 1, ID: strings.Repeat("a", 32), Boot: snapshot.BootID, PolicyHash: policyAdditionHash(state), RootHash: policyAdditionRootHash(root), Phase: "active", Steps: steps}
	f.writeReceipt(t, root, doc)
	inactiveWrite(t, filepath.Join(root, policyAdditionLock), []byte(policyAdditionMarker))
	if err := writeProxyPolicyReceipt(root, proxyPolicyReceipt{Schema: 1, Engine: f.a.ID(), Boot: snapshot.BootID, Digest: proxyPolicyDigest(state), Phase: "restored"}); err != nil {
		t.Fatal(err)
	}
	// The existing inactivity fixture accepts only numeric/read-only commands.
	// Candidate-removal verification also uses the established non-numeric
	// RPDB reader; serve the same inventory for that read, never a mutation.
	f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "ip" && len(args) > 0 && args[0] != "-N" {
			args = append([]string{"-N"}, args...)
		}
		return f.runner.Run(ctx, name, args...)
	})
	return f, root, state
}

func TestColdSingboxRollbackUsesIndependentAbsenceAndRestoredReceipt(t *testing.T) {
	for _, generation := range []bool{false, true} {
		t.Run(fmt.Sprintf("generation=%t", generation), func(t *testing.T) {
			f, root, state := coldRollbackAbsenceFixture(t)
			if generation {
				id := strings.Repeat("a", 32)
				path, err := f.a.policyGenerationRoot(id)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := os.ReadFile(filepath.Join(root, policyAdditionFile))
				var doc policyAdditionDocument
				_ = json.Unmarshal(raw, &doc)
				doc.RootHash = policyAdditionRootHash(path)
				f.writeReceipt(t, path, doc)
				inactiveWrite(t, filepath.Join(path, policyAdditionLock), []byte(policyAdditionMarker))
				_ = os.Remove(filepath.Join(root, policyAdditionFile))
				_ = os.Remove(filepath.Join(root, policyAdditionLock))
				r, _ := f.a.readCandidatePolicyReceipt(root, state)
				r.Generation = id
				if err := writeProxyPolicyReceipt(root, r); err != nil {
					t.Fatal(err)
				}
			}
			before := proxyRollbackRetryFiles(t, f.a.StateRoot, root)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ok, err := f.a.verifyRollbackWithInactiveProof(ctx, Plan{}, root, &f.proof)
			if err != nil || !ok || len(f.runner.seen) < 20 {
				t.Fatal("complete cold restoration did not use independent populated inventories", ok, err, f.runner.seen)
			}
			if after := proxyRollbackRetryFiles(t, f.a.StateRoot, root); !reflect.DeepEqual(before, after) {
				t.Fatal("cold rollback verification wrote runtime, receipts or locks")
			}
			if runtime.GOOS != "linux" {
				if ok, _ := f.a.VerifyRollback(ctx, Plan{}, root); ok {
					t.Fatal("public verification borrowed the private model instead of refusing an unsupported platform")
				}
			}
		})
	}
}

func TestColdSingboxRollbackRejectsUnknownOrRevivedResources(t *testing.T) {
	for _, mode := range []string{"foreign-process", "listener4", "listener6", "foreign-rule", "foreign-forwarding", "foreign-interface", "missing-inventory", "unknown-generation", "missing-receipt", "pending-receipt", "missing-ledger", "pending-ledger", "missing-lock", "cancel", "boot-drift", "snapshot-drift", "receipt-drift"} {
		t.Run(mode, func(t *testing.T) {
			f, root, state := coldRollbackAbsenceFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			switch mode {
			case "foreign-process":
				f.writeProcess(t, 456, "S", "0", "sing-box\x00run\x00")
			case "listener4", "listener6":
				kind, address, remote := "tcp", "0100007F", "00000000"
				if mode == "listener6" {
					kind, address, remote = "tcp6", strings.Repeat("0", 32), strings.Repeat("0", 32)
				}
				row := fmt.Sprintf("0: %s:%04X %s:0000 0A 0:0 0:0 0 0 0 123\n", address, f.a.SOCKSPort, remote)
				inactiveWrite(t, filepath.Join(f.proof.procRoot, "net", kind), []byte(inactiveFixtureSocketHeader+row))
			case "foreign-rule":
				f.runner.rules[4] += "12345: from all lookup " + strconv.Itoa(f.a.Table) + "\n"
			case "foreign-forwarding":
				f.runner.fw["iptables/filter"] = "-P FORWARD ACCEPT\n-N " + f.a.forwardingChain() + "\n"
			case "foreign-interface":
				f.proof.interfaces = func() ([]net.Interface, error) {
					return []net.Interface{{Index: 1, Name: "lo"}, {Index: 2, Name: f.a.Interface}}, nil
				}
			case "missing-inventory":
				_ = os.Remove(filepath.Join(f.proof.procRoot, "net", "tcp6"))
			case "unknown-generation":
				_, _ = f.receipt(t, 1, "intent")
			case "missing-receipt":
				_ = os.Remove(proxyPolicyReceiptPath(root))
			case "pending-receipt":
				r, _ := f.a.readCandidatePolicyReceipt(root, state)
				r.Phase = "unknown"
				_ = writeProxyPolicyReceipt(root, r)
			case "missing-ledger":
				_ = os.Remove(filepath.Join(root, policyAdditionFile))
			case "pending-ledger":
				owned, err := os.ReadFile(filepath.Join(root, policyAdditionFile))
				if err != nil {
					t.Fatal(err)
				}
				var doc policyAdditionDocument
				_ = json.Unmarshal(owned, &doc)
				doc.Steps[0].State = "cleanup-intent"
				f.writeReceipt(t, root, doc)
			case "missing-lock":
				_ = os.Remove(filepath.Join(root, policyAdditionLock))
			case "cancel":
				cancel()
			case "boot-drift", "snapshot-drift", "receipt-drift":
				f.runner.hook = func() {
					switch mode {
					case "boot-drift":
						f.a.bootIdentity = func() (string, error) { return "another-boot", nil }
					case "snapshot-drift":
						s, _ := readProxySnapshot(root)
						s.Config = []byte("changed")
						raw, _ := json.Marshal(s)
						inactiveWrite(t, filepath.Join(root, "snapshot.json"), raw)
					case "receipt-drift":
						r, _ := f.a.readCandidatePolicyReceipt(root, state)
						r.Phase = "unknown"
						_ = writeProxyPolicyReceipt(root, r)
					}
				}
			}
			before := proxyRollbackRetryFiles(t, f.a.StateRoot, root)
			if ok, err := f.a.verifyRollbackWithInactiveProof(ctx, Plan{}, root, &f.proof); ok || err == nil {
				t.Fatal("uncertain cold restoration gained a receipt", mode, ok, err)
			}
			if !strings.HasSuffix(mode, "-drift") && !reflect.DeepEqual(before, proxyRollbackRetryFiles(t, f.a.StateRoot, root)) {
				t.Fatal("negative verification modified files or recreated a missing lock", mode)
			}
		})
	}
}

func TestColdSingboxRollbackDoesNotGrantOtherPriorBaselines(t *testing.T) {
	for _, mode := range []string{"other-boot", "prior-policy", "prior-engine", "prior-sidecar", "prior-package", "prior-runtime-config", "prior-binding"} {
		t.Run(mode, func(t *testing.T) {
			f, root, _ := coldRollbackAbsenceFixture(t)
			s, _ := readProxySnapshot(root)
			switch mode {
			case "other-boot":
				s.BootID = "previous-boot"
			case "prior-policy":
				s.PolicyTracked = true
			case "prior-engine":
				s.EngineWasRunning = true
			case "prior-sidecar":
				s.SidecarWasRunning = true
			case "prior-package":
				s.PackageWasRunning = true
			case "prior-runtime-config":
				s.RuntimeEngineExists = true
			case "prior-binding":
				s.PolicyBinding = &proxyPolicyBinding{Phase: "active"}
			}
			raw, _ := json.Marshal(s)
			inactiveWrite(t, filepath.Join(root, "snapshot.json"), raw)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if ok, _ := f.a.verifyRollbackWithInactiveProof(ctx, Plan{}, root, &f.proof); ok {
				t.Fatal("cold branch accepted a different/unknown prior baseline", mode)
			}
		})
	}
}
