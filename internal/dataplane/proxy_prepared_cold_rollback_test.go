package dataplane

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func coldPreparedRollbackFixture(t *testing.T) (*inactiveFixture, string, PolicyState) {
	t.Helper()
	f, root, state := coldRollbackAbsenceFixture(t)
	for _, name := range []string{policyAdditionFile, policyAdditionLock} {
		if err := os.Remove(filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeProxyPolicyReceipt(root, proxyPolicyReceipt{Schema: 1, Engine: f.a.ID(), Digest: proxyPolicyDigest(state), Phase: "prepared"}); err != nil {
		t.Fatal(err)
	}
	return f, root, state
}

// A preceding adapter can fail Activate after Sing-box passed Canary, before
// Sing-box Activate begins. Rollback then has only Stage's prepared intent.
func TestColdSingboxPreparedRollbackConfirmsIndependentAbsence(t *testing.T) {
	f, root, _ := coldPreparedRollbackFixture(t)
	before := proxyRollbackRetryFiles(t, f.a.StateRoot, root)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if ok, err := f.a.verifyRollbackWithInactiveProof(ctx, Plan{}, root, &f.proof); !ok || err != nil {
		t.Fatal("unactivated candidate was incorrectly fenced", ok, err)
	}
	if len(f.runner.seen) < 20 {
		t.Fatal("did not use independent populated inventories")
	}
	if !reflect.DeepEqual(before, proxyRollbackRetryFiles(t, f.a.StateRoot, root)) {
		t.Fatal("read-only rollback changed prepared intent")
	}
}

func TestColdSingboxPreparedRollbackRefusesEffectsAndAttemptMetadata(t *testing.T) {
	for _, mode := range []string{"unknown", "boot", "generation", "restoration", "no-additions", "retirement", "ledger", "lock", "process", "socket", "kernel", "receipt-missing", "boot-drift"} {
		t.Run(mode, func(t *testing.T) {
			f, root, state := coldPreparedRollbackFixture(t)
			r, err := f.a.readCandidatePolicyReceipt(root, state)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "unknown":
				r.Phase = "unknown"
			case "boot":
				r.Boot = "inactive-fixture-boot"
			case "generation":
				r.Generation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			case "restoration":
				r.RestorationGeneration = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			case "no-additions":
				r.NoAdditions = true
			case "retirement":
				r.RetirementSnapshot = "changed"
			case "ledger":
				inactiveWrite(t, filepath.Join(root, policyAdditionFile), []byte("{}"))
			case "lock":
				inactiveWrite(t, filepath.Join(root, policyAdditionLock), []byte(policyAdditionMarker))
			case "process":
				f.writeProcess(t, 456, "S", "0", "sing-box\x00run\x00")
			case "socket":
				inactiveWrite(t, filepath.Join(f.proof.procRoot, "net", "tcp"), []byte(inactiveFixtureSocketHeader+fmt.Sprintf("0: 0100007F:%04X 00000000:0000 0A 0:0 0:0 0 0 0 123\n", f.a.SOCKSPort)))
			case "kernel":
				f.runner.fw["iptables/filter"] = "-P FORWARD ACCEPT\n-N " + f.a.forwardingChain() + "\n"
			case "boot-drift":
				f.a.bootIdentity = func() (string, error) { return "changed", nil }
			}
			if err := writeProxyPolicyReceipt(root, r); err != nil {
				t.Fatal(err)
			}
			if mode == "receipt-missing" {
				if err := os.Remove(proxyPolicyReceiptPath(root)); err != nil {
					t.Fatal(err)
				}
			}
			before := proxyRollbackRetryFiles(t, f.a.StateRoot, root)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if ok, err := f.a.verifyRollbackWithInactiveProof(ctx, Plan{}, root, &f.proof); ok || err == nil && mode != "boot-drift" {
				t.Fatal("uncertain prepared candidate gained receipt", mode, ok, err)
			}
			if !reflect.DeepEqual(before, proxyRollbackRetryFiles(t, f.a.StateRoot, root)) {
				t.Fatal("verification wrote effects or receipts")
			}
		})
	}
}
