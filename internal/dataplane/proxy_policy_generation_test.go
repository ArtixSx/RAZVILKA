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

func commitScopedGeneration(t *testing.T, f *scopedXrayFixture) (string, PolicyState, proxyPolicyBinding) {
	t.Helper()
	root := stageScopedFixture(t, f)
	ctx := context.Background()
	for _, step := range []func(context.Context, Plan, string) error{f.a.Activate, f.a.Health, f.a.Commit} {
		if err := step(ctx, f.plan, root); err != nil {
			t.Fatal(err)
		}
	}
	state := mustScopedPolicy(t, f.a, root)
	binding, exists, err := f.a.readPolicyBinding(state)
	if err != nil || !exists || binding.Phase != "active" {
		t.Fatal(binding, exists, err)
	}
	return root, state, binding
}

func TestProxyPolicyGenerationSurvivesTransactionReceiptRemoval(t *testing.T) {
	f := scopedXrayTestFixture(t)
	root, state, binding := commitScopedGeneration(t, f)
	if err := os.Remove(filepath.Join(root, policyAdditionFile)); err != nil {
		t.Fatal(err)
	}
	// A fresh adapter has no in-memory receipt or transaction-root dependency.
	fresh := *f.a
	ctx := context.Background()
	if err := fresh.CommittedNodeHealth(ctx, f.plan); err != nil {
		t.Fatal("committed grant depended on discarded transaction", err)
	}
	if err := fresh.Deactivate(ctx); err != nil {
		t.Fatal(err)
	}
	retained, err := fresh.policyGenerationRoot(binding.Generation)
	if err != nil {
		t.Fatal(err)
	}
	status, err := fresh.additionStatus(ctx, state, retained)
	if err != nil || !status.Removed {
		t.Fatal("retained generation lost known settlement", status, err)
	}
	if len(f.processes.running) != 0 {
		t.Fatal("known cleanup left processes running")
	}
}

func TestProxyPolicyGenerationRollbackAfterCommitUsesReceiverAndFreshRestoration(t *testing.T) {
	f := scopedXrayTestFixture(t)
	_, old, prior := commitScopedGeneration(t, f)
	ctx := context.Background()
	root, candidate, receiver := commitScopedGeneration(t, f)
	if receiver.Generation == prior.Generation {
		t.Fatal("candidate reused old generation")
	}
	if err := f.a.Rollback(ctx, f.plan, root); err != nil {
		t.Fatal("outer commit failure could not clean promoted receiver", err)
	}
	if ok, err := f.a.VerifyRollback(ctx, f.plan, root); !ok || err != nil {
		t.Fatal(ok, err)
	}
	current, exists, err := f.a.readPolicyBinding(old)
	if err != nil || !exists || current.Generation == prior.Generation || current.Generation == receiver.Generation {
		t.Fatal("restoration revived consumed receipt", current, err)
	}
	for _, pair := range []struct {
		state PolicyState
		id    string
	}{{old, prior.Generation}, {candidate, receiver.Generation}} {
		path, err := f.a.policyGenerationRoot(pair.id)
		if err != nil {
			t.Fatal(err)
		}
		status, err := f.a.additionStatus(ctx, pair.state, path)
		if err != nil || !status.Removed {
			t.Fatal("old generation not retained as removed", status, err)
		}
	}
}

func TestProxyPolicyGenerationMissingOrUnknownNeverFallsBackOrStopsRuntime(t *testing.T) {
	for _, mode := range []string{"missing-binding", "missing-receipt", "corrupt-receipt", "boot", "generation-path"} {
		t.Run(mode, func(t *testing.T) {
			f := scopedXrayTestFixture(t)
			_, state, binding := commitScopedGeneration(t, f)
			path, err := f.a.policyGenerationRoot(binding.Generation)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing-binding":
				err = os.Remove(f.a.policyBindingPath())
			case "missing-receipt":
				err = os.Remove(filepath.Join(path, policyAdditionFile))
			case "corrupt-receipt":
				err = os.WriteFile(filepath.Join(path, policyAdditionFile), []byte("{}"), 0600)
			case "boot":
				f.a.bootIdentity = func() (string, error) { return "another-boot", nil }
			case "generation-path":
				binding.Generation = "../../foreign"
				err = f.a.writePolicyBinding(binding)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := make(map[string]bool)
			for id, running := range f.processes.running {
				before[id] = running
			}
			base := f.a.Runner
			mutated := false
			f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if len(receiptMutationCalls([]string{name + " " + strings.Join(args, " ")})) != 0 {
					mutated = true
				}
				return base.Run(ctx, name, args...)
			})
			if err := f.a.Deactivate(context.Background()); !errors.Is(err, ErrProxyPolicyUnknown) || mutated || !reflect.DeepEqual(before, f.processes.running) {
				t.Fatal("unknown committed receipt granted destructive fallback", err, mutated)
			}
			if _, exists, err := f.a.loadPolicy(); err != nil || !exists {
				t.Fatal("unknown runtime lost private identity", state, err)
			}
		})
	}
}

func TestProxyPolicyGenerationUnknownRestorationKeepsPendingReference(t *testing.T) {
	f := scopedXrayTestFixture(t)
	_, old, prior := commitScopedGeneration(t, f)
	ctx := context.Background()
	root := stageScopedFixture(t, f)
	if err := f.a.Activate(ctx, f.plan, root); err != nil {
		t.Fatal(err)
	}
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
		t.Fatal("restoration did not retain uncertainty", err)
	}
	binding, exists, err := f.a.readPolicyBinding(old)
	if err != nil || !exists || binding.Phase != "pending" || binding.Generation == prior.Generation {
		t.Fatal("unknown restoration overwritten by historical authority", binding, err)
	}
	path, err := f.a.policyGenerationRoot(binding.Generation)
	if err != nil {
		t.Fatal(err)
	}
	status, err := f.a.additionStatus(ctx, old, path)
	if err != nil || !status.Unknown {
		t.Fatal(status, err)
	}
	f.a.Runner = base
	before := make(map[string]bool)
	for id, running := range f.processes.running {
		before[id] = running
	}
	if err := f.a.Deactivate(ctx); !errors.Is(err, ErrProxyPolicyUnknown) || !reflect.DeepEqual(before, f.processes.running) {
		t.Fatal("unknown restoration permitted teardown", err)
	}
}
