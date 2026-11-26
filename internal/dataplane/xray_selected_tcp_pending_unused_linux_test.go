//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestXrayPendingFirstApplyRetriesAfterLANReadRefusal(t *testing.T) {
	f := newXrayPreparedManagerFixture(t, nil)
	f.cut = nil // Continue past the shared fixture's default cut after LAN Validate.
	activationFailure := errors.New("fixture WAN guard refused")
	lanReadFailure := errors.New("fixture LAN read unavailable")
	allowRead := false
	failed, refused := false, false
	binding := f.checks.gate.Binding
	guard := binding.ApplyGuard
	binding.ApplyGuard = func(ctx context.Context, lan *LANPolicyRuntimePlan, effect LANPolicyEffect) error {
		if err := guard(ctx, lan, effect); err != nil {
			return err
		}
		failed = true
		return activationFailure
	}
	reader := f.checks.readSource
	f.checks.readSource = networkPolicyInventoryCallback(func(ctx context.Context, id netidentity.Identity) (BackendInventorySnapshot, error) {
		e := f.x.material.execution
		e.mu.Lock()
		retired := e.retired
		e.mu.Unlock()
		if failed && retired && !allowRead {
			refused = true
			return BackendInventorySnapshot{}, lanReadFailure
		}
		return reader.readInventory(ctx, id)
	})
	result, err := f.x.manager.Apply(f.ctx, f.plan, nil)
	if !failed || !refused || !errors.Is(err, activationFailure) || !errors.Is(err, lanReadFailure) || result.State != "rollback-failed" ||
		result.RollbackVerified || len(result.Resources) != 1 || result.Resources[0].State != "unused" || !f.x.manager.HasPendingManagedXraySelectedTCP() {
		for _, step := range result.Steps {
			t.Logf("adapter=%s phase=%s state=%s", step.Adapter, step.Phase, step.State)
		}
		t.Fatalf("unexpected original cut: activation=%t refusal=%t state=%s owner=%t", failed, refused, result.State, f.x.manager.HasPendingManagedXraySelectedTCP())
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(f.ctx), time.Minute)
	defer cancel()
	owner := f.x.manager.retainedXrayOwner()
	resource := owner.execution.resource
	before, err := f.x.manager.Status()
	if err != nil || before.Plan == nil || before.Plan.Ready {
		t.Fatal("failed Apply still appears ready", err)
	}
	failedPlan := *before.Plan
	pre := owner.execution.preResource
	bound, end, err := owner.operation(ctx, owner.execution.material.cleanup, false)
	if err != nil {
		t.Fatal(err)
	}
	original := owner.execution.plan
	dispatch := pre.rollbackDispatchPlan(bound, owner.scope, f.x.adapter, failedPlan)
	drift := failedPlan
	drift.Revision++
	if !xraySelectedTCPSamePlan(original, dispatch) ||
		xraySelectedTCPSamePlan(original, pre.rollbackDispatchPlan(bound, owner.scope, f.x.adapter, drift)) ||
		pre.rollbackDispatchPlan(ctx, owner.scope, f.x.adapter, failedPlan).Ready ||
		pre.rollbackDispatchPlan(bound, nil, f.x.adapter, failedPlan).Ready {
		t.Fatal("retry comparison changed authority or accepted changed route intent")
	}
	end()
	if pre.rollbackDispatchPlan(bound, owner.scope, f.x.adapter, failedPlan).Ready {
		t.Fatal("closed cleanup could substitute readiness")
	}
	if terminal, err := f.x.manager.JoinPendingManagedXraySelectedTCP(ctx); err == nil || terminal != nil || !f.x.manager.HasPendingManagedXraySelectedTCP() {
		t.Fatal("LAN still unavailable, but pending ownership changed")
	}
	allowRead = true
	// Swapping either author's file or the config for byte-identical content
	// must keep the same pending lifetime. Restore the original fixture inode
	// after each refusal so the remaining positive case uses that same owner.
	for _, file := range []string{
		filepath.Join(owner.scope.root, "execution.json"),
		filepath.Join(owner.scope.managerRoot, "latest-execution.json"),
		filepath.Join(resource.rootPath, resource.definition.Process.ConfigName),
	} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(file, file+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
		if terminal, err := f.x.manager.JoinPendingManagedXraySelectedTCP(ctx); err == nil || terminal != nil ||
			f.x.manager.retainedXrayOwner() != owner || !owner.pending || resource.descriptorsClosed || owner.scope.execution.RollbackVerified {
			t.Fatalf("accepted a different inode for %s", filepath.Base(file))
		}
		if err := os.Rename(file+".original", file); err != nil {
			t.Fatal(err)
		}
	}
	terminal, err := f.x.manager.JoinPendingManagedXraySelectedTCP(ctx)
	if err != nil || terminal == nil || f.x.manager.HasPendingManagedXraySelectedTCP() {
		t.Fatal("original Manager failed to finish remaining LAN rollback and Xray readback")
	}
	if resource.versionUsed || resource.startUsed || resource.selectorUsed || resource.child != nil || f.x.model.starts != 0 || f.x.model.stops != 0 {
		t.Fatal("never-started cleanup invoked a process or a selector")
	}
	if err := terminal.Close(); err != nil {
		t.Fatal("closing original terminal", err)
	}
	status, statusErr := f.x.manager.Status()
	if statusErr != nil || status.Execution == nil || !status.Execution.RollbackVerified || status.Execution.State != "rolled-back" {
		t.Fatal("terminal rollback not published")
	}
}
