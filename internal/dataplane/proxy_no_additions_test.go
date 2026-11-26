package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type proxyBeforeAddFailure struct {
	*ProxyTunnelAdapter
	cause error
}

func (a *proxyBeforeAddFailure) Activate(ctx context.Context, _ Plan, root string) error {
	state, err := a.readStagedPolicy(root)
	if err != nil {
		return err
	}
	if err := a.beginCandidatePolicy(root, state); err != nil {
		return err
	}
	prior, exists, err := a.loadPolicy()
	if err != nil || !exists {
		return errors.Join(errors.New("missing prior test policy"), err)
	}
	if err := a.removeCommittedPolicy(ctx, prior); err != nil {
		return err
	}
	return a.cause
}

func TestProxyNoAdditionsRestorationVerifiesLivePrior(t *testing.T) {
	f := scopedXrayTestFixture(t)
	_, _, prior := commitScopedGeneration(t, f)
	root := stageScopedFixture(t, f)
	cause := errors.New("failure before candidate additions")
	adapter := &proxyBeforeAddFailure{ProxyTunnelAdapter: f.a, cause: cause}
	ctx := context.Background()
	if err := adapter.Activate(ctx, f.plan, root); !errors.Is(err, cause) {
		t.Fatal(err)
	}
	if err := adapter.Rollback(ctx, f.plan, root); err != nil {
		t.Fatal(err)
	}
	if ok, err := adapter.VerifyRollback(ctx, f.plan, root); !ok || err != nil {
		t.Fatal("no-additions restoration remained fenced", ok, err)
	}
	state := mustScopedPolicy(t, f.a, root)
	binding, exists, err := f.a.readPolicyBinding(state)
	if err != nil || !exists || binding.Generation == prior.Generation {
		t.Fatal("restoration did not acquire a fresh grant", binding, exists, err)
	}
	// NoAdditions cannot forgive an unexpectedly present ledger or another boot.
	if err := os.WriteFile(filepath.Join(root, policyAdditionFile), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if ok, err := adapter.VerifyRollback(ctx, f.plan, root); ok || err == nil {
		t.Fatal("unexpected candidate ledger was ignored", ok, err)
	}
	if err := os.Remove(filepath.Join(root, policyAdditionFile)); err != nil {
		t.Fatal(err)
	}
	f.a.bootIdentity = func() (string, error) { return "another-boot", nil }
	if err := f.a.verifyCandidateReceipt(ctx, root, state, false); err == nil {
		t.Fatal("no-additions settlement survived a boot change")
	}
}

func TestManagerNoAdditionsRestorationRecordsVerifiedRollback(t *testing.T) {
	f := scopedXrayTestFixture(t)
	commitScopedGeneration(t, f)
	m := New(t.TempDir())
	m.FreshProfile = f.a.FreshProfile
	cause := errors.New("failure before candidate additions")
	if err := m.Register(&proxyBeforeAddFailure{ProxyTunnelAdapter: f.a, cause: cause}); err != nil {
		t.Fatal(err)
	}
	plan := f.plan
	plan.SchemaVersion, plan.PlanID, plan.Digest, plan.Ready = SchemaVersion, "dp-no-additions", strings.Repeat("a", 64), true
	plan.Adapters = []string{f.a.ID()}
	execution, err := m.Apply(context.Background(), plan, nil)
	if !errors.Is(err, cause) || execution.State != "rolled-back" || !execution.RollbackVerified {
		t.Fatal("manager retained recovery fence after exact restoration", execution.State, execution.RollbackVerified, err)
	}
	if err := m.CheckExecutionRecovery(context.Background()); err != nil {
		t.Fatal("settled rollback blocked the next operation", err)
	}
}
