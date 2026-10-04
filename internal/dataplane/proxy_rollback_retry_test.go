package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type proxyRollbackRetryProcesses struct {
	base         ProcessController
	start, stop  []string
	failStopID   string
	failStopOnce bool
}

func (p *proxyRollbackRetryProcesses) Start(ctx context.Context, spec ProcessSpec) error {
	p.start = append(p.start, spec.ID)
	return p.base.Start(ctx, spec)
}

func (p *proxyRollbackRetryProcesses) Stop(ctx context.Context, spec ProcessSpec) error {
	p.stop = append(p.stop, spec.ID)
	if p.failStopOnce && spec.ID == p.failStopID {
		p.failStopOnce = false
		return errors.New("transient rollback Stop failure")
	}
	return p.base.Stop(ctx, spec)
}

func (p *proxyRollbackRetryProcesses) Running(spec ProcessSpec) bool {
	return p.base.Running(spec)
}

func proxyRollbackRetryFixture(t *testing.T) (*scopedXrayFixture, string, PolicyState) {
	t.Helper()
	f := scopedXrayTestFixture(t)
	_, prior, _ := commitScopedGeneration(t, f)
	root := stageScopedFixture(t, f)
	if err := f.a.Activate(context.Background(), f.plan, root); err != nil {
		t.Fatal(err)
	}
	return f, root, prior
}

func proxyRollbackRetryMutates(name string, args []string) bool {
	if name == "ip" {
		if len(args) > 0 && args[0] == "-6" {
			args = args[1:]
		}
		if len(args) < 2 {
			return false
		}
		if args[0] == "route" || args[0] == "rule" || args[0] == "link" {
			switch args[1] {
			case "add", "del", "delete", "replace", "flush", "change", "append", "set":
				return true
			}
		}
	}
	if name == "iptables" || name == "ip6tables" {
		for _, arg := range args {
			switch arg {
			case "-N", "-A", "-I", "-D", "-X", "-F", "-P", "-E", "-Z":
				return true
			}
		}
	}
	return false
}

func proxyRollbackRetryFiles(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	files := map[string]string{}
	for n, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			value := info.Mode().String()
			if info.Mode().IsRegular() {
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				value += "\x00" + string(data)
			}
			files[strconv.Itoa(n)+"/"+relative] = value
			return nil
		})
		if err != nil {
			t.Fatal("read private rollback state", err)
		}
	}
	return files
}

func TestProxyRollbackRetryAfterTransientStopUsesFreshAdapter(t *testing.T) {
	f, root, prior := proxyRollbackRetryFixture(t)
	ctx := context.Background()
	processes := &proxyRollbackRetryProcesses{base: f.a.Processes, failStopID: f.a.engineProcess().ID, failStopOnce: true}
	f.a.Processes = processes
	if err := f.a.Rollback(ctx, f.plan, root); err == nil {
		t.Fatal("transient Stop failure accepted")
	}
	receipt, err := f.a.readCandidatePolicyReceipt(root, mustScopedPolicy(t, f.a, root))
	if err != nil || receipt.Phase != "restoring" {
		t.Fatal("failure did not retain restoring phase", receipt, err)
	}
	status, err := f.a.additionStatus(ctx, mustScopedPolicy(t, f.a, root), root)
	if err != nil || !status.Removed || status.Unknown {
		t.Fatal("candidate cleanup was not settled before retry", status, err)
	}
	// Retry uses durable state, rather than any receipt retained in the adapter.
	fresh := *f.a
	if err := fresh.Rollback(ctx, f.plan, root); err != nil {
		t.Fatal("known candidate cleanup permanently fenced safe retry", err)
	}
	if ok, err := fresh.VerifyRollback(ctx, f.plan, root); err != nil || !ok {
		t.Fatal("retry did not restore exact live A", ok, err)
	}
	if err := fresh.CommittedNodeHealth(ctx, f.plan); err != nil {
		t.Fatal("restored A is not healthy", err)
	}
	binding, exists, err := fresh.readPolicyBinding(prior)
	if err != nil || !exists || binding.Phase != "active" {
		t.Fatal("retry did not retain new active restoration generation", binding, exists, err)
	}
}

func TestProxyRollbackRetryUnknownRestorationDoesNotMutate(t *testing.T) {
	f, root, prior := proxyRollbackRetryFixture(t)
	ctx := context.Background()
	processes := &proxyRollbackRetryProcesses{base: f.a.Processes}
	f.a.Processes = processes
	base, injected := f.a.Runner, false
	f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		out, err := base.Run(ctx, name, args...)
		if !injected && name == "ip" && strings.Contains(strings.Join(args, " "), "rule add") && err == nil {
			injected = true
			return out, errors.New("lost restoration add acknowledgement")
		}
		return out, err
	})
	if err := f.a.Rollback(ctx, f.plan, root); !errors.Is(err, ErrProxyPolicyUnknown) || !injected {
		t.Fatal("restoration uncertainty was not retained", err, injected)
	}
	binding, exists, err := f.a.readPolicyBinding(prior)
	if err != nil || !exists || binding.Phase != "pending" {
		t.Fatal("unknown restoration lost pending reference", binding, exists, err)
	}
	generation, err := f.a.policyGenerationRoot(binding.Generation)
	if err != nil {
		t.Fatal(err)
	}
	status, err := f.a.additionStatus(ctx, prior, generation)
	if err != nil || !status.Unknown {
		t.Fatal("lost acknowledgement became live restoration authority", status, err)
	}
	before := proxyRollbackRetryFiles(t, f.a.StateRoot, root)
	processes.start, processes.stop = nil, nil
	mutations := []string{}
	f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if proxyRollbackRetryMutates(name, args) {
			mutations = append(mutations, name+" "+strings.Join(args, " "))
		}
		return base.Run(ctx, name, args...)
	})
	fresh := *f.a
	if err := fresh.Rollback(ctx, f.plan, root); !errors.Is(err, ErrProxyPolicyUnknown) {
		t.Fatal("unknown restoration acquired retry authority", err)
	}
	if len(mutations) != 0 || len(processes.start) != 0 || len(processes.stop) != 0 {
		t.Fatal("unknown retry changed kernel/firewall/processes", mutations, processes.start, processes.stop)
	}
	if after := proxyRollbackRetryFiles(t, fresh.StateRoot, root); !reflect.DeepEqual(before, after) {
		t.Fatal("unknown retry changed private files or pending generation")
	}
	current, exists, err := fresh.readPolicyBinding(prior)
	if err != nil || !exists || current != binding {
		t.Fatal("unknown retry replaced pending reference", current, exists, err)
	}
}

func TestProxyRollbackRetryPreservesForeignPolicyInsertedBetweenAttempts(t *testing.T) {
	for _, mode := range []string{"default", "selector"} {
		t.Run(mode, func(t *testing.T) {
			f, root, prior := proxyRollbackRetryFixture(t)
			ctx := context.Background()
			processes := &proxyRollbackRetryProcesses{base: f.a.Processes, failStopID: f.a.engineProcess().ID, failStopOnce: true}
			f.a.Processes = processes
			if err := f.a.Rollback(ctx, f.plan, root); err == nil {
				t.Fatal("transient Stop failure accepted")
			}
			receipt, err := f.a.readCandidatePolicyReceipt(root, mustScopedPolicy(t, f.a, root))
			if err != nil || receipt.Phase != "restoring" {
				t.Fatal(receipt, err)
			}
			foreign := ""
			defaultKey := "4/" + strconv.Itoa(prior.Table)
			if mode == "default" {
				// Same complete tuple, but installed AFTER B's cleanup receipt.
				foreign = "default dev " + prior.Interface + " proto boot scope link metric 0\n"
				f.runner.defaults[defaultKey] = foreign
			} else {
				rules, err := kernelRulesForPolicy(prior)
				if err != nil {
					t.Fatal(err)
				}
				for _, rule := range rules {
					if rule.family == 4 {
						foreign = fmt.Sprintf("%d: from %s to %s lookup %d", rule.priority, rule.source, rule.destination, rule.table)
						break
					}
				}
				if foreign == "" {
					t.Fatal("fixture has no IPv4 selector")
				}
				f.runner.policy.foreignIPv4 = append(f.runner.policy.foreignIPv4, foreign)
			}
			base := f.a.Runner
			mutations := []string{}
			f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == "ip" && proxyRollbackRetryMutates(name, args) {
					mutations = append(mutations, name+" "+strings.Join(args, " "))
				}
				return base.Run(ctx, name, args...)
			})
			fresh := *f.a
			if err := fresh.Rollback(ctx, f.plan, root); err == nil {
				t.Fatal("foreign policy accepted for restoration")
			}
			if len(mutations) != 0 {
				t.Fatal("retry reused consumed B grant or mutated occupied policy slots", mutations)
			}
			if mode == "default" && f.runner.defaults[defaultKey] != foreign || mode == "selector" && !reflect.DeepEqual(f.runner.policy.foreignIPv4, []string{foreign}) {
				t.Fatal("foreign policy was changed by retry")
			}
		})
	}
}

func TestProxyRollbackRetrySnapshotOnlyPreservesExactActiveA(t *testing.T) {
	f := scopedXrayTestFixture(t)
	_, state, binding := commitScopedGeneration(t, f)
	ctx := context.Background()
	root := privateScopedXrayFixtureDir(t)
	if err := f.a.Snapshot(ctx, f.plan, root); err != nil {
		t.Fatal(err)
	}
	processes := &proxyRollbackRetryProcesses{base: f.a.Processes}
	f.a.Processes = processes
	base := f.a.Runner
	mutations := []string{}
	f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if proxyRollbackRetryMutates(name, args) {
			mutations = append(mutations, name+" "+strings.Join(args, " "))
		}
		return base.Run(ctx, name, args...)
	})
	before := proxyRollbackRetryFiles(t, f.a.StateRoot, root)
	fresh := *f.a
	if err := fresh.Rollback(ctx, f.plan, root); err != nil {
		t.Fatal("snapshot-only unchanged A could not finish without replay", err)
	}
	if len(mutations) != 0 || len(processes.start) != 0 || len(processes.stop) != 0 {
		t.Fatal("snapshot-only rollback replayed kernel/firewall/processes", mutations, processes.start, processes.stop)
	}
	current, exists, err := fresh.readPolicyBinding(state)
	if err != nil || !exists || current != binding {
		t.Fatal("snapshot-only rollback replaced active A binding", current, exists, err)
	}
	if after := proxyRollbackRetryFiles(t, fresh.StateRoot, root); !reflect.DeepEqual(before, after) {
		t.Fatal("snapshot-only no-op changed private files or generations")
	}
	if err := fresh.CommittedNodeHealth(ctx, f.plan); err != nil {
		t.Fatal("snapshot-only rollback damaged healthy A", err)
	}
}

func TestProxyRollbackRetrySnapshotOnlyChangedAuthorityIsFenced(t *testing.T) {
	for _, mode := range []string{"binding", "runtime-file", "boot", "inactive-snapshot"} {
		t.Run(mode, func(t *testing.T) {
			f := scopedXrayTestFixture(t)
			_, _, binding := commitScopedGeneration(t, f)
			ctx := context.Background()
			root := privateScopedXrayFixtureDir(t)
			if err := f.a.Snapshot(ctx, f.plan, root); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "binding":
				binding.Generation = strings.Repeat("f", 32)
				if err := f.a.writePolicyBinding(binding); err != nil {
					t.Fatal(err)
				}
			case "runtime-file":
				if err := os.WriteFile(f.a.engineConfigPath(), []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "boot":
				f.a.bootIdentity = func() (string, error) { return "another-boot", nil }
			case "inactive-snapshot":
				snapshot, err := readProxySnapshot(root)
				if err != nil {
					t.Fatal(err)
				}
				// Model a snapshot whose readback could not prove active policy.
				snapshot.PolicyWasActive = false
				data, err := json.Marshal(snapshot)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "snapshot.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			processes := &proxyRollbackRetryProcesses{base: f.a.Processes}
			f.a.Processes = processes
			base := f.a.Runner
			mutations := []string{}
			f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if proxyRollbackRetryMutates(name, args) {
					mutations = append(mutations, name+" "+strings.Join(args, " "))
				}
				return base.Run(ctx, name, args...)
			})
			before := proxyRollbackRetryFiles(t, f.a.StateRoot, root)
			fresh := *f.a
			if err := fresh.Rollback(ctx, f.plan, root); !errors.Is(err, ErrProxyPolicyUnknown) {
				t.Fatal("changed snapshot-only authority accepted", err)
			}
			if len(mutations) != 0 || len(processes.start) != 0 || len(processes.stop) != 0 {
				t.Fatal("changed snapshot-only authority allowed mutation", mutations, processes.start, processes.stop)
			}
			if after := proxyRollbackRetryFiles(t, fresh.StateRoot, root); !reflect.DeepEqual(before, after) {
				t.Fatal("changed snapshot-only authority overwrote private state")
			}
		})
	}
}

func TestProxyRollbackRetrySnapshotOnlyColdNewBindingIsFenced(t *testing.T) {
	for _, mode := range []string{"active", "pending", "tracked-journal", "malformed-journal"} {
		t.Run(mode, func(t *testing.T) {
			f := scopedXrayTestFixture(t)
			ctx := context.Background()
			root := privateScopedXrayFixtureDir(t)
			if err := f.a.Snapshot(ctx, f.plan, root); err != nil {
				t.Fatal(err)
			}
			snapshot, err := readProxySnapshot(root)
			if err != nil || snapshot.PolicyExists || snapshot.PolicyTracked || snapshot.PolicyBinding != nil {
				t.Fatal("fixture is not a cold snapshot without policy", snapshot, err)
			}
			// This reference/journal appeared after the empty snapshot. Its
			// previous absence cannot authorize overwriting the new state.
			if err := os.MkdirAll(f.a.StateRoot, 0700); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "active", "pending":
				binding := proxyPolicyBinding{Schema: 1, Engine: f.a.ID(), Digest: proxyPolicyDigest(snapshot.Policy), Generation: strings.Repeat("e", 32), Phase: mode}
				if err := f.a.writePolicyBinding(binding); err != nil {
					t.Fatal(err)
				}
			case "tracked-journal":
				state := testEarlyPolicy()
				if err := f.a.savePolicyJournal(state, true); err != nil {
					t.Fatal(err)
				}
			case "malformed-journal":
				if err := os.WriteFile(f.a.policyPath(), []byte(`{"addition_receipt_version":`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			processes := &proxyRollbackRetryProcesses{base: f.a.Processes}
			f.a.Processes = processes
			base := f.a.Runner
			mutations := []string{}
			f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if proxyRollbackRetryMutates(name, args) {
					mutations = append(mutations, name+" "+strings.Join(args, " "))
				}
				return base.Run(ctx, name, args...)
			})
			before := proxyRollbackRetryFiles(t, f.a.StateRoot, root)
			fresh := *f.a
			if err := fresh.Rollback(ctx, f.plan, root); !errors.Is(err, ErrProxyPolicyUnknown) {
				t.Fatal("empty historical snapshot granted mutation of new binding", err)
			}
			if len(mutations) != 0 || len(processes.start) != 0 || len(processes.stop) != 0 {
				t.Fatal("new binding permitted snapshot-only cleanup", mutations, processes.start, processes.stop)
			}
			if after := proxyRollbackRetryFiles(t, fresh.StateRoot, root); !reflect.DeepEqual(before, after) {
				t.Fatal("empty historical snapshot overwrote newly appeared binding")
			}
		})
	}
}

func TestProxyRollbackRetryStagedColdNewTrackedJournalIsFenced(t *testing.T) {
	f := scopedXrayTestFixture(t)
	ctx := context.Background()
	root := stageScopedFixture(t, f)
	snapshot, err := readProxySnapshot(root)
	if err != nil || snapshot.PolicyExists || snapshot.PolicyTracked || snapshot.PolicyBinding != nil {
		t.Fatal("fixture is not staged from cold untracked history", snapshot, err)
	}
	if err := f.a.Activate(ctx, f.plan, root); err != nil {
		t.Fatal(err)
	}
	processes := &proxyRollbackRetryProcesses{base: f.a.Processes, failStopID: f.a.engineProcess().ID, failStopOnce: true}
	f.a.Processes = processes
	if err := f.a.Rollback(ctx, f.plan, root); err == nil {
		t.Fatal("transient Stop failure accepted")
	}
	state := mustScopedPolicy(t, f.a, root)
	receipt, err := f.a.readCandidatePolicyReceipt(root, state)
	if err != nil || receipt.Phase != "restoring" {
		t.Fatal("early cold rollback did not retain retry phase", receipt, err)
	}
	if err := f.a.savePolicyJournal(state, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(f.a.policyBindingPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fixture unexpectedly has a binding for new tracked journal", err)
	}
	processes.start, processes.stop = nil, nil
	base := f.a.Runner
	mutations := []string{}
	f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if proxyRollbackRetryMutates(name, args) {
			mutations = append(mutations, name+" "+strings.Join(args, " "))
		}
		return base.Run(ctx, name, args...)
	})
	before := proxyRollbackRetryFiles(t, f.a.StateRoot, root)
	fresh := *f.a
	if err := fresh.Rollback(ctx, f.plan, root); !errors.Is(err, ErrProxyPolicyUnknown) {
		t.Fatal("cold staged retry ignored new tracked journal's missing binding", err)
	}
	if len(mutations) != 0 || len(processes.start) != 0 || len(processes.stop) != 0 {
		t.Fatal("new tracked journal allowed cold staged retry mutation", mutations, processes.start, processes.stop)
	}
	if after := proxyRollbackRetryFiles(t, fresh.StateRoot, root); !reflect.DeepEqual(before, after) {
		t.Fatal("cold staged retry overwrote newly tracked journal")
	}
}
