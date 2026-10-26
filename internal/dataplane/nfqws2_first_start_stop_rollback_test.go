package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
)

func TestNFQWS2FirstStartPartialStopCompensatesOnlyAfterFreshAbsence(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, kind := range []string{"transient-kernel", "canceled-forward-guard", "persistent-kernel", "foreign-pid", "unknown-pid", "foreign-config", "foreign-overlay", "config-during-absence", "overlay-during-absence", "pid-during-absence"} {
		t.Run(kind, func(t *testing.T) {
			f := newFirstStartFixture(t)
			f.plan.PlanID = "dp-1111111111111111"
			f.plan.Revision = 1
			f.apply(t)
			prior, err := f.a.readLease()
			if err != nil {
				t.Fatal(err)
			}
			originalPID := f.identity.PID
			// Reproduce a live owned process whose mangle hooks disappeared. The
			// stock Stop model still removes its ordinary NAT remnants and own queue.
			f.ownedRules = false
			natRemnant := true
			guardAllowed := true
			observations := 0
			foreignPath, foreignBytes := "", ""
			observe := f.a.firstStartObservation
			f.a.firstStartObservation = func(ctx context.Context, full bool) error {
				if !f.running {
					observations++
					if natRemnant {
						return nfqws2InactiveAt("observation", nfqws2InactiveAt("kernel", ErrNFQWSManagedKernelOwner))
					}
					if observations == 1 || kind == "persistent-kernel" {
						return nfqws2InactiveAt("observation", nfqws2InactiveAt("kernel", ErrNFQWSManagedKernelOwner))
					}
				}
				if observations == 2 && !f.running {
					switch kind {
					case "config-during-absence":
						foreignPath, foreignBytes = f.a.ConfigPath, readText(t, f.a.ConfigPath)+"# foreign after capture\n"
					case "overlay-during-absence":
						foreignPath, foreignBytes = f.a.ConfigPath+".run", "FOREIGN=2\n"
					case "pid-during-absence":
						foreignPath, foreignBytes = f.a.firstStartPIDPath(), "999\n"
					}
					if foreignPath != "" {
						writeStockText(t, foreignPath, foreignBytes)
					}
				}
				return observe(ctx, full)
			}
			f.afterStop = func() {
				natRemnant = false
				guardAllowed = false
				switch kind {
				case "foreign-pid":
					foreign := *prior.FirstStart.Process
					foreign.Start = "foreign"
					f.a.firstStartProcessRead = func(int) (components.NFQWSRuntimeProcessIdentity, error) { return foreign, nil }
				case "unknown-pid":
					f.a.firstStartProcessRead = func(int) (components.NFQWSRuntimeProcessIdentity, error) {
						return components.NFQWSRuntimeProcessIdentity{}, os.ErrPermission
					}
				case "foreign-config":
					writeStockText(t, f.a.ConfigPath, readText(t, f.a.ConfigPath)+"# foreign edit\n")
				case "foreign-overlay":
					writeStockText(t, f.a.ConfigPath+".run", "FOREIGN=1\n")
				}
			}
			stop := Plan{SchemaVersion: SchemaVersion, PlanID: "dp-2222222222222222", Digest: strings.Repeat("b", 64), Revision: 2, Ready: true, RetiringAdapters: []string{"nfqws2"}}
			stopContext := firstStartContext(t)
			if kind == "canceled-forward-guard" {
				stopContext = WithReviewGuard(stopContext, func(c context.Context) error {
					if !guardAllowed {
						return context.Canceled
					}
					return c.Err()
				})
			}
			result, err := f.m.Apply(stopContext, stop, nil)
			if err == nil || natRemnant {
				t.Fatal("Stop refusal was hidden", result, err)
			}
			lease, readErr := f.a.readLease()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if kind == "transient-kernel" || kind == "canceled-forward-guard" {
				if result.State != "rolled-back" || !result.RollbackVerified || !f.running || !f.ownedRules || f.identity.PID == originalPID || !nfqws2RollbackLeaseEqual(lease, prior) {
					t.Fatalf("prior runtime not restored: state=%s verified=%v running=%v rules=%v pid=%d err=%v", result.State, result.RollbackVerified, f.running, f.ownedRules, f.identity.PID, err)
				}
				if observations < 2 {
					t.Fatal("restart borrowed the failed absence observation")
				}
			} else {
				if result.State != "rollback-failed" || result.RollbackVerified || f.running || f.ownedRules || !reflect.DeepEqual(lease, prior) {
					t.Fatalf("unknown/foreign state was adopted: state=%s verified=%v running=%v err=%v", result.State, result.RollbackVerified, f.running, err)
				}
				rollbackFailed := false
				for _, step := range result.Steps {
					if step.Phase == "rollback" && step.State == "failed" {
						rollbackFailed = true
					}
				}
				if !rollbackFailed {
					t.Fatal("partial Stop compensation reported a no-op PASS", result.Steps)
				}
			}
			if foreignPath != "" && readText(t, foreignPath) != foreignBytes {
				t.Fatal("foreign source image overwritten during compensation")
			}
			if f.a.firstStartReview != nil {
				t.Fatal("compensation leaked native review")
			}
			f.assertWriterReleased(t)
		})
	}
}

func TestNFQWS2FirstStartRollbackVerificationRequiresRestoredPacketPath(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, kind := range []string{"exact", "missing-hook", "wrong-interface", "wrong-processed-mark", "foreign-queue", "missing-pre-hook", "missing-pre-chain", "terminal-before-pre-hook"} {
		t.Run(kind, func(t *testing.T) {
			f := newFirstStartFixture(t)
			f.plan.PlanID = "dp-1111111111111111"
			f.apply(t)
			previous, exists, err := f.m.Committed()
			if err != nil || !exists {
				t.Fatal(err)
			}
			stop := Plan{SchemaVersion: SchemaVersion, RetiringAdapters: []string{"nfqws2"}}
			root := filepath.Join(t.TempDir(), "nfqws2")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			if err := f.a.snapshotRetiring(firstStartContext(t), stop, previous, root); err != nil {
				t.Fatal(err)
			}
			rules := nfqwsHealthRulesFixture
			switch kind {
			case "missing-hook":
				rules = strings.ReplaceAll(rules, "-A POSTROUTING -j nfqws_post\n", "")
			case "wrong-interface":
				rules = strings.ReplaceAll(rules, "-o eth3", "-o eth4")
			case "wrong-processed-mark":
				rules = strings.ReplaceAll(rules, "0x40000000/0x40000000", "0x20000000/0x20000000")
			case "foreign-queue":
				rules = strings.ReplaceAll(rules, "--queue-num 300", "--queue-num 301")
			case "missing-pre-hook":
				rules = strings.ReplaceAll(rules, "-A PREROUTING -j nfqws_pre\n", "")
			case "missing-pre-chain":
				rules = strings.Replace(nfqws2HealthWithoutLines(rules, "-A nfqws_pre "), ":nfqws_pre - [0:0]\n", "", 1)
			case "terminal-before-pre-hook":
				rules = strings.ReplaceAll(rules, "-A PREROUTING -j nfqws_pre\n", "-A PREROUTING -j ACCEPT\n-A PREROUTING -j nfqws_pre\n")
			}
			runner := f.a.Runner
			f.a.Runner = nfqws2RunFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == f.a.IPTablesSave {
					return []byte(rules), nil
				}
				return runner.Run(ctx, name, args...)
			})
			probes := 0
			f.a.HealthProbe = func(context.Context, string) error { probes++; return errors.New("web probe must not run") }
			confirmed, err := f.a.VerifyRollback(firstStartContext(t), stop, root)
			if confirmed != (kind == "exact") || (err == nil) != (kind == "exact") || probes != 0 || !f.running {
				t.Fatalf("bad restored kernel scope: kind=%s confirmed=%v err=%v probes=%d", kind, confirmed, err, probes)
			}
		})
	}
}

func TestNFQWS2FirstStartPartialStopExplicitRollbackKeepsForwardGuard(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.plan.PlanID = "dp-1111111111111111"
	f.apply(t)
	prior, err := f.a.readLease()
	if err != nil {
		t.Fatal(err)
	}
	previous, _, err := f.m.Committed()
	if err != nil {
		t.Fatal(err)
	}
	stop := Plan{SchemaVersion: SchemaVersion, RetiringAdapters: []string{"nfqws2"}}
	root := filepath.Join(t.TempDir(), "nfqws2")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := f.a.snapshotRetiring(firstStartContext(t), stop, previous, root); err != nil {
		t.Fatal(err)
	}
	observe := f.a.firstStartObservation
	f.a.firstStartObservation = func(ctx context.Context, full bool) error {
		if !f.running {
			return ErrNFQWSManagedKernelOwner
		}
		return observe(ctx, full)
	}
	if err := f.a.Deactivate(firstStartContext(t)); err == nil {
		t.Fatal("partial Stop unexpectedly passed")
	}
	f.a.firstStartObservation = observe
	cause := errors.New("ordinary explicit rollback still requires its caller guard")
	ctx := WithReviewGuard(firstStartContext(t), func(context.Context) error { return cause })
	if err := f.a.Rollback(ctx, stop, root); !errors.Is(err, cause) {
		t.Fatal("ordinary rollback bypassed guard", err)
	}
	lease, err := f.a.readLease()
	if err != nil || !reflect.DeepEqual(lease, prior) || f.running || f.ownedRules || f.a.firstStartReview != nil {
		t.Fatal("guard refusal changed prior ownership", err)
	}
	f.assertWriterReleased(t)
}

func TestNFQWS2FirstStartPartialStopCanceledCleanupRetainsFence(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.plan.PlanID = "dp-1111111111111111"
	f.apply(t)
	prior, err := f.a.readLease()
	if err != nil {
		t.Fatal(err)
	}
	previous, _, err := f.m.Committed()
	if err != nil {
		t.Fatal(err)
	}
	stop := Plan{SchemaVersion: SchemaVersion, RetiringAdapters: []string{"nfqws2"}}
	root := filepath.Join(t.TempDir(), "nfqws2")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := f.a.snapshotRetiring(firstStartContext(t), stop, previous, root); err != nil {
		t.Fatal(err)
	}
	observe := f.a.firstStartObservation
	f.a.firstStartObservation = func(ctx context.Context, full bool) error {
		if !f.running {
			return ErrNFQWSManagedKernelOwner
		}
		return observe(ctx, full)
	}
	if err := f.a.Deactivate(firstStartContext(t)); err == nil {
		t.Fatal("partial Stop unexpectedly passed")
	}
	cleanup, cancel := context.WithCancel(firstStartContext(t))
	defer cancel()
	f.a.firstStartObservation = func(ctx context.Context, full bool) error { err := observe(ctx, full); cancel(); return err }
	if err := f.a.rollbackOriginalFirstStart(cleanup, stop, root); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled cleanup lost its bound", err)
	}
	lease, err := f.a.readLease()
	if err != nil || !reflect.DeepEqual(lease, prior) || f.running || f.ownedRules || f.a.firstStartReview != nil {
		t.Fatal("canceled cleanup changed ownership", err)
	}
	f.assertWriterReleased(t)
}
