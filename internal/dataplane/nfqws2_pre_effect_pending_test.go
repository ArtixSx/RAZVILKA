package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A consumer/kernel/source model only. The actual Manager Apply compensation
// closure, journal publications, control/FD witness and pending state run here;
// this fake consumer cannot be issued by the production material factory.
type preEffectPendingConsumer struct {
	*fakeAdapter
	f           *preEffectLANFixture
	snapshotted bool
	proof       bool
}

func (a *preEffectPendingConsumer) Snapshot(context.Context, Plan, string) error {
	a.f.modelSource()
	a.snapshotted = true
	return nil
}
func (a *preEffectPendingConsumer) Rollback(context.Context, Plan, string) error {
	a.f.e.retired = true
	return nil
}
func (a *preEffectPendingConsumer) VerifyRollback(ctx context.Context, _ Plan, _ string) (bool, error) {
	return a.proof, ctx.Err()
}

func pendingPreEffectLANManager(t *testing.T) (*preEffectLANFixture, *preEffectPendingConsumer) {
	t.Helper()
	f := newPreEffectLANFixture(t)
	m := f.e.material.manager
	a := &preEffectPendingConsumer{fakeAdapter: &fakeAdapter{id: "nfqws2"}, f: f, proof: true}
	// Model only the consumer I/O boundary; production owners independently
	// require the registered concrete NFQ adapter and cannot accept this map.
	m.Adapters["nfqws2"] = a
	f.e.plan.Adapters = []string{NetworkPolicyAdapterID, "nfqws2"}
	f.e.plan.NetworkProfileID = executionNetwork
	f.e.selection.plan = cloneExecutionResourcePlan(f.e.plan)
	if err := os.Remove(f.root); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Dir(f.root)); err != nil {
		t.Fatal(err)
	}
	postSnapshot := 0
	m.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
	f.ctx = WithReviewGuard(f.ctx, func(context.Context) error {
		if a.snapshotted {
			postSnapshot++
			if postSnapshot > 1 {
				return f.physical
			}
		}
		return nil
	})
	f.physical = errors.New("modeled packet fence revoked before Stage")
	f.refuse = "read-open"
	result, err := m.Apply(f.ctx, f.e.plan, nil)
	if err == nil || result.State != "rollback-failed" || result.RollbackVerified || !m.HasPendingManagedNFQWS() {
		t.Fatal("actual original no-effect failure not retained", result, err)
	}
	for _, step := range result.Steps {
		if step.Phase == "stage" || step.Phase == "activate" {
			t.Fatal("model crossed pre-Stage boundary", step)
		}
	}
	if !f.e.retired || f.reads != 1 {
		t.Fatal("initial consumer/gate observations not exercised", f.e.retired, f.reads)
	}
	f.refuse = ""
	return f, a
}

func readPreEffectTerminal(t *testing.T, f *preEffectLANFixture) {
	t.Helper()
	var latest, transaction Execution
	for path, target := range map[string]*Execution{filepath.Join(f.e.material.managerRoot, "latest-execution.json"): &latest, filepath.Join(filepath.Dir(f.root), "execution.json"): &transaction} {
		data, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(data, target) != nil {
			t.Fatal("original journal", err)
		}
	}
	if latest.State != "rolled-back" || transaction.State != "rolled-back" || latest.RollbackVerified || transaction.RollbackVerified {
		t.Fatal("no-effect completion forged mutation rollback", latest.State, latest.RollbackVerified, transaction.State, transaction.RollbackVerified)
	}
}

func TestNFQWSPreEffectPendingActualCompensationSettlesWithoutMutationReceipt(t *testing.T) {
	f, _ := pendingPreEffectLANManager(t)
	m := f.e.material.manager
	// Isolate the actual captured compensation's terminal predicate. Public
	// Join's original-source preflight is tested separately below.
	if err := m.pendingNFQ.join(f.ctx); err != nil {
		t.Fatal("fresh verified no-effect compensation cannot complete", err)
	}
	readPreEffectTerminal(t, f)
}

func TestNFQWSPreEffectPendingSlowCompensationOutlivesCallerAndClearsOwner(t *testing.T) {
	f, _ := pendingPreEffectLANManager(t)
	m := f.e.material.manager
	caller, cancel := context.WithCancel(f.ctx)
	defer cancel()
	entered, leave := make(chan struct{}), make(chan struct{})
	f.afterRead = func() { close(entered); <-leave }
	done := make(chan error, 1)
	go func() { done <- m.JoinPendingManagedNFQWS(caller) }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatal("original pending preflight/compensation refused", err)
	case <-f.ctx.Done():
		t.Fatal("compensation did not enter")
	}
	// A delayed original cleanup has already been admitted. Cancelling its
	// short caller must neither cancel the bounded original compensation nor
	// prevent non-I/O pending bookkeeping after it independently completes.
	cancel()
	close(leave)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("slow original compensation failed", err)
		}
	case <-f.ctx.Done():
		t.Fatal("original bounded compensation did not join")
	}
	if caller.Err() == nil || m.HasPendingManagedNFQWS() {
		t.Fatal("post-compensation bookkeeping retained a completed owner")
	}
	readPreEffectTerminal(t, f)
}

func TestNFQWSPreEffectPendingCompletionNeverSurvivesFailedNextCycle(t *testing.T) {
	f, consumer := pendingPreEffectLANManager(t)
	m := f.e.material.manager
	planPath := filepath.Join(m.StateRoot, "latest-plan.json")
	prior, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	f.afterRead = func() {
		if err := os.Remove(planPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(planPath, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.pendingNFQ.join(f.ctx); err == nil || !m.HasPendingManagedNFQWS() {
		t.Fatal("failed final publication released original owner")
	}
	f.afterRead = nil
	if err := os.Remove(planPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planPath, prior, 0600); err != nil {
		t.Fatal(err)
	}
	consumer.proof = false
	if err := m.pendingNFQ.join(f.ctx); err == nil || !m.HasPendingManagedNFQWS() {
		t.Fatal("previous completion replaced fresh consumer readback")
	}
	consumer.proof = true
	f.refuse = "read-open"
	if err := m.pendingNFQ.join(f.ctx); err == nil {
		t.Fatal("previous completion replaced fresh kernel/source readback")
	}
	f.refuse = ""
	if err := m.JoinPendingManagedNFQWS(f.ctx); err != nil || m.HasPendingManagedNFQWS() {
		t.Fatal("fresh complete retry did not settle", err)
	}
	readPreEffectTerminal(t, f)
}
