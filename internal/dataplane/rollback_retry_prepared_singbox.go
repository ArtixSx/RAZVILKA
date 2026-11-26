package dataplane

import (
	"context"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

// Admit only the observed first mixed addition: Sing-box passed Canary but NFQ
// failed Activate before Sing-box activation. Close/retirement and general mixed
// recovery remain unchanged; the added Sing-box participant is read-only.
func (m *Manager) reviewPreparedColdSingboxRollback(ctx context.Context, planID, digest string, proof *proxyInactiveProof) (failedRollback, bool) {
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
	if err != nil || !exists || !preparedColdSingboxRollbackHistory(planID, digest, plan, previous, *latest) {
		return failedRollback{}, false
	}
	nfq, ok := m.adapter("nfqws2")
	if !ok {
		return failedRollback{}, false
	}
	registered, ok := m.adapter("sing-box")
	singbox, concrete := registered.(*ProxyTunnelAdapter)
	if !ok || !concrete || singbox.Configs == nil || singbox.StateRoot != filepath.Join(m.StateRoot, "sing-box") {
		return failedRollback{}, false
	}
	view := singbox
	candidateRoot := filepath.Join(root, "sing-box")
	snapshot, err := readProxySnapshot(candidateRoot)
	if err != nil || snapshot.EngineID != "sing-box" || view.checkSnapshotSidecar(snapshot) != nil ||
		snapshot.PolicyExists || snapshot.PolicyWasActive || snapshot.PolicyTracked || snapshot.PolicyBinding != nil ||
		snapshot.EngineWasRunning || snapshot.SidecarWasRunning || snapshot.PackageWasRunning ||
		snapshot.RuntimeEngineExists || snapshot.RuntimeSideExists || snapshot.TransportExists || snapshot.NodeManifestExists || snapshot.NodeInterfaceExists ||
		len(snapshot.RuntimeEngine) != 0 || len(snapshot.RuntimeSidecar) != 0 || len(snapshot.Transport) != 0 || len(snapshot.Evidence) != 0 ||
		len(snapshot.NodeManifest) != 0 || len(snapshot.NodeInterface) != 0 {
		return failedRollback{}, false
	}
	staged, err := view.rollbackPolicyState(candidateRoot)
	if err != nil {
		return failedRollback{}, false
	}
	receipt, err := view.readCandidatePolicyReceipt(candidateRoot, staged)
	if err != nil || !proxyColdCandidateNeverActivated(candidateRoot, receipt) {
		return failedRollback{}, false
	}
	singOnly := &preparedColdSingboxRollback{Adapter: view, view: view, plan: plan, root: candidateRoot, snapshot: snapshot, staged: staged, receipt: receipt, proof: proof}
	// Prove complete absence before journaling or restoring NFQ. This wrapper
	// never falls through to generic Sing-box cleanup or process changes.
	if err := singOnly.Rollback(ctx, plan, candidateRoot); err != nil {
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
	// The independently decoded closing image is equal but shares no mutable
	// slices with the wrapper's original binding. Later input drift must still
	// fail exact equality, including a change of nil/empty shape.
	return failedRollback{latest: latest, root: root, plan: closingPlan, previous: previous, prepared: []Adapter{nfq, singOnly}}, true
}

func preparedColdSingboxRollbackHistory(planID, digest string, plan, previous Plan, execution Execution) bool {
	if plan.SchemaVersion != SchemaVersion || previous.SchemaVersion != SchemaVersion || plan.PlanID != planID || plan.Digest != digest || plan.State != "rollback-failed" ||
		previous.State != "committed" || previous.PlanID == planID || !validPlanID(previous.PlanID) || !validPlanDigest(previous.Digest) || !previous.Ready || previous.Noop || previous.SafeMode || plan.Noop || plan.SafeMode ||
		!slices.Equal(plan.Adapters, []string{"nfqws2", "sing-box"}) || !slices.Equal(previous.Adapters, []string{"nfqws2"}) ||
		plan.LAN != nil || previous.LAN != nil || plan.DNS != nil || previous.DNS != nil || plan.SuspendDNS || previous.SuspendDNS || plan.DiscardDNS || previous.DiscardDNS ||
		plan.DomainPolicy != nil || previous.DomainPolicy != nil || plan.SyntheticDNS != nil || previous.SyntheticDNS != nil || len(plan.RetiringAdapters) != 0 || len(previous.RetiringAdapters) != 0 ||
		!systemprobe.ValidWANProfileID(plan.NetworkProfileID) || execution.PlanID != planID || execution.Digest != digest || execution.State != "rollback-failed" || execution.RollbackVerified ||
		len(execution.Resources) != 0 || execution.ResourcePlanID != "" || len(execution.Steps) < 12 || len(execution.Steps) > maxRecoveryJournalSteps {
		return false
	}
	started, err := time.Parse(time.RFC3339Nano, execution.StartedAt)
	finished, finishErr := time.Parse(time.RFC3339Nano, execution.FinishedAt)
	if err != nil || finishErr != nil || finished.Before(started) {
		return false
	}
	expected := [][3]string{{"nfqws2", "snapshot", "passed"}, {"sing-box", "snapshot", "passed"},
		{"nfqws2", "stage", "passed"}, {"sing-box", "stage", "passed"}, {"nfqws2", "validate", "passed"}, {"sing-box", "validate", "passed"},
		{"sing-box", "canary", "passed"}, {"nfqws2", "activate", "failed"}, {"sing-box", "rollback", "passed"}, {"nfqws2", "rollback", "passed"},
		{"nfqws2", "verify-rollback", "passed"}, {"sing-box", "verify-rollback", "failed"}}
	for i, step := range execution.Steps {
		if i < len(expected) {
			if [3]string{step.Adapter, step.Phase, step.State} != expected[i] {
				return false
			}
		} else if !slices.Contains([]string{"nfqws2", "sing-box"}, step.Adapter) || !slices.Contains([]string{"retry-rollback", "retry-verify-rollback"}, step.Phase) || !slices.Contains([]string{"passed", "failed", "running"}, step.State) {
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

// The embedded adapter supplies identity only. Retry cannot convert Stage-only
// intent into cleanup authority, even if metadata/runtime changes after review.
type preparedColdSingboxRollback struct {
	Adapter
	view     *ProxyTunnelAdapter
	plan     Plan
	root     string
	snapshot proxySnapshot
	staged   PolicyState
	receipt  proxyPolicyReceipt
	proof    *proxyInactiveProof
}

func (a *preparedColdSingboxRollback) Rollback(ctx context.Context, plan Plan, root string) error {
	ctx, cancel := context.WithTimeout(ctx, proxyInactiveBudget)
	defer cancel()
	if root != a.root || !reflect.DeepEqual(plan, a.plan) {
		return ErrProxyPolicyUnknown
	}
	snapshot, err := readProxySnapshot(root)
	if err != nil || !reflect.DeepEqual(snapshot, a.snapshot) {
		return ErrProxyPolicyUnknown
	}
	staged, err := a.view.rollbackPolicyState(root)
	if err != nil || !reflect.DeepEqual(staged, a.staged) {
		return ErrProxyPolicyUnknown
	}
	receipt, err := a.view.readCandidatePolicyReceipt(root, staged)
	if err != nil || receipt != a.receipt || !proxyColdCandidateNeverActivated(root, receipt) {
		return ErrProxyPolicyUnknown
	}
	if err := verifyRestoredFile(snapshot.ConfigPath, snapshot.Config, snapshot.ConfigExisted); err != nil {
		return err
	}
	ok, err := a.view.verifyRollbackWithInactiveProof(ctx, plan, root, a.proof)
	if err != nil {
		return err
	}
	if !ok {
		return ErrProxyPolicyUnknown
	}
	return nil
}

func (a *preparedColdSingboxRollback) VerifyRollback(ctx context.Context, plan Plan, root string) (bool, error) {
	err := a.Rollback(ctx, plan, root)
	return err == nil, err
}
