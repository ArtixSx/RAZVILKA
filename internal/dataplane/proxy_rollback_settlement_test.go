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

// Cut after every add was durably acknowledged, while saving the committed
// policy journal fails. A new adapter must finish this same generation.
func TestProxyRollbackRetrySettlesCompleteRestorationWithoutRuntimeReplay(t *testing.T) {
	for _, phase := range []string{"active", "pending"} {
		t.Run(phase, func(t *testing.T) {
			f, root, prior := proxyRollbackRetryFixture(t)
			ctx := context.Background()
			processes := &proxyRollbackRetryProcesses{base: f.a.Processes}
			f.a.Processes = processes
			journal, err := os.ReadFile(f.a.policyPath())
			if err != nil {
				t.Fatal(err)
			}
			rules, err := kernelRulesForPolicy(prior)
			if err != nil || len(rules) == 0 {
				t.Fatal(err)
			}
			base, adds, injected := f.a.Runner, 0, false
			marker := filepath.Join(f.a.policyPath(), "keep")
			f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				out, err := base.Run(ctx, name, args...)
				if name == "ip" && strings.Contains(strings.Join(args, " "), "rule add") && err == nil {
					adds++
					if adds == len(rules) {
						if err := os.Remove(f.a.policyPath()); err != nil {
							t.Fatal(err)
						}
						if err := os.Mkdir(f.a.policyPath(), 0700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(marker, []byte("keep"), 0600); err != nil {
							t.Fatal(err)
						}
						injected = true
					}
				}
				return out, err
			})
			if err := f.a.Rollback(ctx, f.plan, root); err == nil || !injected {
				t.Fatal("late journal failure did not cut restoration", err, injected)
			}
			binding, exists, err := f.a.readPolicyBinding(prior)
			if err != nil || !exists || binding.Phase != "active" {
				t.Fatal(binding, exists, err)
			}
			receipt, err := f.a.readCandidatePolicyReceipt(root, mustScopedPolicy(t, f.a, root))
			if err != nil || receipt.Phase != "restoring" || receipt.RestorationGeneration != binding.Generation {
				t.Fatal("late failure lost transaction's exact restoration reference", receipt, err)
			}
			path, _ := f.a.policyGenerationRoot(binding.Generation)
			status, err := f.a.additionStatus(ctx, prior, path)
			if err != nil || !status.Complete || status.Unknown {
				t.Fatal("late cut did not retain all durable ACKs", status, err)
			}
			if phase == "pending" {
				// Model a process cut between the last durable ACK and publishing
				// active. The transaction reference and ledger are unchanged.
				binding.Phase, binding.ReceiptID = "pending", ""
				if err := f.a.writePolicyBinding(binding); err != nil {
					t.Fatal(err)
				}
			}
			// Repair only the deliberately blocked fixture file path.
			if err := os.Remove(marker); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(f.a.policyPath()); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.a.policyPath(), journal, 0600); err != nil {
				t.Fatal(err)
			}
			processes.start, processes.stop = nil, nil
			mutations := []string{}
			f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if proxyRollbackRetryMutates(name, args) {
					mutations = append(mutations, name+" "+strings.Join(args, " "))
				}
				return base.Run(ctx, name, args...)
			})
			fresh := *f.a
			if err := fresh.Rollback(ctx, f.plan, root); err != nil {
				t.Fatal("complete restoration could not finish", err)
			}
			current, exists, err := fresh.readPolicyBinding(prior)
			if err != nil || !exists || current.Generation != binding.Generation || current.Phase != "active" || current.ReceiptID != status.ID {
				t.Fatal("retry replaced rather than settled acknowledged generation", current, err)
			}
			if len(mutations) != 0 || len(processes.start) != 0 || len(processes.stop) != 0 {
				t.Fatal("late retry replayed runtime operations", mutations, processes.start, processes.stop)
			}
			if ok, err := fresh.VerifyRollback(ctx, f.plan, root); !ok || err != nil {
				t.Fatal("late settlement is not verified A", ok, err)
			}
		})
	}
}

func TestProxyRollbackRetryRejectsChangedAuthorityBeforeMutation(t *testing.T) {
	for _, mode := range []string{"boot", "missing-receipt", "corrupt-receipt", "foreign-binding"} {
		t.Run(mode, func(t *testing.T) {
			f, root, prior := proxyRollbackRetryFixture(t)
			ctx := context.Background()
			processes := &proxyRollbackRetryProcesses{base: f.a.Processes, failStopID: f.a.engineProcess().ID, failStopOnce: true}
			f.a.Processes = processes
			if err := f.a.Rollback(ctx, f.plan, root); err == nil {
				t.Fatal("early cut did not fail")
			}
			switch mode {
			case "boot":
				f.a.bootIdentity = func() (string, error) { return "another-boot", nil }
			case "missing-receipt":
				if err := os.Remove(filepath.Join(root, policyAdditionFile)); err != nil {
					t.Fatal(err)
				}
			case "corrupt-receipt":
				if err := os.WriteFile(filepath.Join(root, policyAdditionFile), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-binding":
				binding, exists, err := f.a.readPolicyBinding(prior)
				if err != nil || !exists {
					t.Fatal(binding, exists, err)
				}
				binding.Generation = strings.Repeat("a", 32)
				if err := f.a.writePolicyBinding(binding); err != nil {
					t.Fatal(err)
				}
			}
			before := proxyRollbackRetryFiles(t, f.a.StateRoot, root)
			processes.start, processes.stop = nil, nil
			base, mutations := f.a.Runner, []string{}
			f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if proxyRollbackRetryMutates(name, args) {
					mutations = append(mutations, name+" "+strings.Join(args, " "))
				}
				return base.Run(ctx, name, args...)
			})
			fresh := *f.a
			if err := fresh.Rollback(ctx, f.plan, root); !errors.Is(err, ErrProxyPolicyUnknown) {
				t.Fatal("changed authority granted retry", err)
			}
			if len(mutations) != 0 || len(processes.start) != 0 || len(processes.stop) != 0 || !reflect.DeepEqual(before, proxyRollbackRetryFiles(t, fresh.StateRoot, root)) {
				t.Fatal("changed authority retry mutated runtime or files", mutations, processes.start, processes.stop)
			}
		})
	}
}
