package dataplane

import (
	"context"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

// This is only the observed first Xray addition that refused Stage before
// publishing any candidate file. It does not extend Close/retirement or the
// general Xray rollback contract. Every Xray operation below remains read-only.
func (m *Manager) reviewUnstagedColdXrayRollback(ctx context.Context, planID, digest string, proof *proxyInactiveProof) (failedRollback, bool) {
	if m.retainedNFQOwner() != nil || m.retainedXrayOwner() != nil || m.retainedWGOwner() != nil || m.HasPendingManagedNFQWS() || ctx.Err() != nil {
		return failedRollback{}, false
	}
	var latest, transaction *Execution
	root := filepath.Join(m.StateRoot, "transactions", planID)
	if exists, err := readOptionalJournal(filepath.Join(m.StateRoot, "latest-execution.json"), &latest); err != nil || !exists || latest == nil {
		return failedRollback{}, false
	}
	if exists, err := readOptionalJournal(filepath.Join(root, "execution.json"), &transaction); err != nil || !exists || !reflect.DeepEqual(latest, transaction) {
		return failedRollback{}, false
	}
	plan, exists, err := m.latestLocked()
	if err != nil || !exists {
		return failedRollback{}, false
	}
	previous, exists, err := m.committedLocked()
	if err != nil || !exists || !unstagedColdXrayRollbackHistory(planID, digest, plan, previous, *latest) {
		return failedRollback{}, false
	}
	nfq, ok := m.adapter("nfqws2")
	if !ok {
		return failedRollback{}, false
	}
	registered, ok := m.adapter("xray")
	xray, concrete := registered.(*ProxyTunnelAdapter)
	if !ok || !concrete || xray.Configs == nil || xray.StateRoot != filepath.Join(m.StateRoot, "xray") {
		return failedRollback{}, false
	}
	view, frozen, err := xray.dispatchXrayPlan(plan, filepath.Join(root, "xray"), true)
	if err != nil {
		return failedRollback{}, false
	}
	snapshot, err := readProxySnapshot(filepath.Join(root, "xray"))
	if err != nil {
		return failedRollback{}, false
	}
	configured, err := view.Configs.ReadExpert("xray", "main")
	if err != nil || configured.Path != snapshot.ConfigPath || snapshot.ConfigExisted || len(snapshot.Config) != 0 || len(snapshot.StagedConfig) != 0 ||
		len(snapshot.RuntimeEngine) != 0 || len(snapshot.RuntimeSidecar) != 0 || len(snapshot.Transport) != 0 || len(snapshot.Evidence) != 0 ||
		len(snapshot.NodeManifest) != 0 || len(snapshot.NodeInterface) != 0 || !reflect.DeepEqual(snapshot.Policy, PolicyState{}) {
		return failedRollback{}, false
	}
	xrayOnly := &unstagedColdXrayRollback{Adapter: view, view: view, plan: frozen, root: filepath.Join(root, "xray"), snapshot: snapshot, proof: proof}
	// Before any recovery journal or NFQ restoration, prove that no Xray
	// teardown can be needed. The same complete observer runs at both steps.
	if err := xrayOnly.Rollback(ctx, frozen, xrayOnly.root); err != nil {
		return failedRollback{}, false
	}
	// A complete kernel observation can take time. Its success must not
	// outlive either original execution image or either reviewed plan.
	var closingLatest, closingTransaction *Execution
	if exists, err := readOptionalJournal(filepath.Join(m.StateRoot, "latest-execution.json"), &closingLatest); err != nil || !exists || !reflect.DeepEqual(latest, closingLatest) {
		return failedRollback{}, false
	}
	if exists, err := readOptionalJournal(filepath.Join(root, "execution.json"), &closingTransaction); err != nil || !exists || !reflect.DeepEqual(latest, closingTransaction) {
		return failedRollback{}, false
	}
	closingPlan, exists, err := m.latestLocked()
	if err != nil || !exists || !reflect.DeepEqual(plan, closingPlan) {
		return failedRollback{}, false
	}
	closingPrevious, exists, err := m.committedLocked()
	if err != nil || !exists || !reflect.DeepEqual(previous, closingPrevious) || ctx.Err() != nil {
		return failedRollback{}, false
	}
	return failedRollback{latest: latest, root: root, plan: plan, previous: previous, prepared: []Adapter{nfq, xrayOnly}}, true
}

func unstagedColdXrayRollbackHistory(planID, digest string, plan, previous Plan, execution Execution) bool {
	if plan.SchemaVersion != SchemaVersion || previous.SchemaVersion != SchemaVersion || plan.PlanID != planID || plan.Digest != digest || plan.State != "rollback-failed" ||
		previous.State != "committed" || previous.PlanID == planID || !validPlanID(previous.PlanID) || !validPlanDigest(previous.Digest) || !previous.Ready || previous.Noop || previous.SafeMode || plan.Noop || plan.SafeMode ||
		!slices.Equal(plan.Adapters, []string{"nfqws2", "xray"}) || !slices.Equal(previous.Adapters, []string{"nfqws2"}) ||
		plan.LAN != nil || previous.LAN != nil || plan.DNS != nil || previous.DNS != nil || plan.SuspendDNS || previous.SuspendDNS || plan.DiscardDNS || previous.DiscardDNS ||
		plan.DomainPolicy != nil || previous.DomainPolicy != nil || plan.SyntheticDNS != nil || previous.SyntheticDNS != nil || len(plan.RetiringAdapters) != 0 || len(previous.RetiringAdapters) != 0 ||
		!systemprobe.ValidWANProfileID(plan.NetworkProfileID) || execution.PlanID != planID || execution.Digest != digest || execution.State != "rollback-failed" || execution.RollbackVerified ||
		len(execution.Resources) != 0 || execution.ResourcePlanID != "" || len(execution.Steps) < 8 || len(execution.Steps) > maxRecoveryJournalSteps {
		return false
	}
	started, err := time.Parse(time.RFC3339Nano, execution.StartedAt)
	finished, finishErr := time.Parse(time.RFC3339Nano, execution.FinishedAt)
	if err != nil || finishErr != nil || finished.Before(started) {
		return false
	}
	expected := [][3]string{{"nfqws2", "snapshot", "passed"}, {"xray", "snapshot", "passed"}, {"nfqws2", "stage", "passed"}, {"xray", "stage", "failed"},
		{"xray", "rollback", "failed"}, {"nfqws2", "rollback", "passed"}, {"nfqws2", "verify-rollback", "passed"}, {"xray", "verify-rollback", "passed"}}
	for i, step := range execution.Steps {
		if i < len(expected) {
			if [3]string{step.Adapter, step.Phase, step.State} != expected[i] {
				return false
			}
		} else if !slices.Contains([]string{"nfqws2", "xray"}, step.Adapter) || !slices.Contains([]string{"retry-rollback", "retry-verify-rollback"}, step.Phase) || !slices.Contains([]string{"passed", "failed", "running"}, step.State) {
			return false
		}
		at, err := time.Parse(time.RFC3339Nano, step.StartedAt)
		if err != nil || at.Before(started) {
			return false
		}
		if step.State == "running" {
			if step.FinishedAt != "" {
				return false
			}
			continue
		}
		end, err := time.Parse(time.RFC3339Nano, step.FinishedAt)
		if err != nil || end.Before(at) {
			return false
		}
	}
	return true
}

// The embedded adapter supplies its identity only. Neither method can fall
// through to generic cleanup if an artifact appears after admission.
type unstagedColdXrayRollback struct {
	Adapter
	view     *ProxyTunnelAdapter
	plan     Plan
	root     string
	snapshot proxySnapshot
	proof    *proxyInactiveProof
}

func (a *unstagedColdXrayRollback) Rollback(ctx context.Context, plan Plan, root string) error {
	if root != a.root || !reflect.DeepEqual(plan, a.plan) {
		return ErrProxyPolicyUnknown
	}
	handled, err := a.view.verifyUnstagedColdXray(ctx, root, a.snapshot, a.proof)
	if !handled {
		return ErrProxyPolicyUnknown
	}
	return err
}

func (a *unstagedColdXrayRollback) VerifyRollback(ctx context.Context, plan Plan, root string) (bool, error) {
	err := a.Rollback(ctx, plan, root)
	return err == nil, err
}
