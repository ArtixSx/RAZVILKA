package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
)

// The transaction names restoration A before publishing its global binding.
// State hashes alone cannot distinguish A and B with identical selectors.
func (a *ProxyTunnelAdapter) publishProxyRestoration(root, id string) error {
	state, err := a.readStagedPolicy(root)
	if err != nil {
		return ErrProxyPolicyUnknown
	}
	receipt, err := a.readCandidatePolicyReceipt(root, state)
	if err != nil || receipt.Phase != "restoring" || receipt.RestorationGeneration != "" {
		return ErrProxyPolicyUnknown
	}
	receipt.RestorationGeneration = id
	if err := a.checkXrayTransactionSnapshot(); err != nil {
		return err
	}
	return writeProxyPolicyReceipt(root, receipt)
}

func (a *ProxyTunnelAdapter) verifyUnstagedProxyRestoration(ctx context.Context, root string, snapshot proxySnapshot) error {
	var err error
	a, err = a.xrayPreviousView(snapshot)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(proxyPolicyReceiptPath(root)); !errors.Is(err, os.ErrNotExist) {
		return ErrProxyPolicyUnknown
	}
	if !snapshot.PolicyTracked || snapshot.PolicyBinding == nil {
		return ErrProxyPolicyUnknown
	}
	binding, exists, err := a.readPolicyBinding(snapshot.Policy)
	if err != nil || !exists || binding != *snapshot.PolicyBinding || binding.Phase != "active" {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	policy, exists, err := a.loadPolicy()
	if err != nil || !exists || !reflect.DeepEqual(policy, snapshot.Policy) {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	if err := a.verifyCommittedReceipt(ctx, policy); err != nil {
		return err
	}
	if err := a.verifyProxyRestorationRuntime(ctx, snapshot, snapshot.Policy); err != nil {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	return a.checkXrayTransactionSnapshot()
}

// All classification and runtime checks precede any retry mutation. A removed
// candidate grants no authority over an uncertain or unrelated restoration.
func (a *ProxyTunnelAdapter) resumeProxyPolicyRestoration(ctx context.Context, root string, candidate PolicyState, snapshot proxySnapshot, receipt proxyPolicyReceipt) (bool, error) {
	var err error
	a, err = a.xrayPreviousView(snapshot)
	if err != nil {
		return false, err
	}
	boot, err := a.currentBootIdentity()
	if err != nil || receipt.Boot == "" || receipt.Boot != boot || snapshot.BootID != "" && snapshot.BootID != boot {
		return false, ErrProxyPolicyUnknown
	}
	additionRoot := root
	if receipt.Generation != "" {
		additionRoot, err = a.policyGenerationRoot(receipt.Generation)
		if err != nil {
			return false, err
		}
	}
	status, err := a.additionStatus(ctx, candidate, additionRoot)
	if err != nil || !status.Removed || status.Unknown || receipt.Generation != "" && status.ID != receipt.Generation {
		return false, errors.Join(ErrProxyPolicyUnknown, err)
	}
	if receipt.RestorationGeneration == "" {
		return false, a.verifyPreRestorationBinding(ctx, snapshot, candidate, receipt)
	}
	if !snapshot.PolicyExists || !snapshot.PolicyWasActive || !snapshot.EngineWasRunning || !snapshot.SidecarWasRunning {
		return false, ErrProxyPolicyUnknown
	}
	binding, exists, err := a.readPolicyBinding(snapshot.Policy)
	if err != nil || !exists || binding.Generation != receipt.RestorationGeneration || binding.Phase != "pending" && binding.Phase != "active" {
		return false, errors.Join(ErrProxyPolicyUnknown, err)
	}
	additionRoot, err = a.policyGenerationRoot(receipt.RestorationGeneration)
	if err != nil {
		return false, err
	}
	status, err = a.additionStatus(ctx, snapshot.Policy, additionRoot)
	if err != nil || !status.Complete || status.Unknown || binding.ReceiptID != "" && binding.ReceiptID != status.ID {
		return false, errors.Join(ErrProxyPolicyUnknown, err)
	}
	// A complete durable ledger can settle a cut after the last ACK even if
	// writing the active binding/journal failed. Kernel readback cannot supply
	// the ACK; it only verifies that this exact acknowledged runtime survived.
	if err := a.verifyProxyRestorationRuntime(ctx, snapshot, candidate); err != nil {
		return false, errors.Join(ErrProxyPolicyUnknown, err)
	}
	if err := a.checkXrayTransactionSnapshot(); err != nil {
		return false, err
	}
	binding.Phase, binding.ReceiptID = "active", status.ID
	if err := a.writePolicyBinding(binding); err != nil {
		return false, err
	}
	if err := a.savePolicyJournal(snapshot.Policy, true); err != nil {
		return false, err
	}
	return true, nil
}

func (a *ProxyTunnelAdapter) verifyPreRestorationBinding(ctx context.Context, snapshot proxySnapshot, candidate PolicyState, receipt proxyPolicyReceipt) error {
	// Before A starts, the global reference can only be the consumed prior A
	// or B's consumed promoted receiver. Missing tracked or foreign references
	// fail closed; neither may be overwritten with historical authority.
	priorID := ""
	if snapshot.PolicyBinding != nil {
		priorID = snapshot.PolicyBinding.Generation
	}
	for _, prior := range []struct {
		state PolicyState
		id    string
	}{
		{snapshot.Policy, priorID},
		{candidate, receipt.Generation},
	} {
		if prior.id == "" {
			continue
		}
		binding, exists, err := a.readPolicyBinding(prior.state)
		if err != nil || !exists || binding.Generation != prior.id || binding.Phase == "pending" {
			continue
		}
		path, err := a.policyGenerationRoot(prior.id)
		if err != nil {
			return err
		}
		status, err := a.additionStatus(ctx, prior.state, path)
		if err != nil || !status.Removed || status.Unknown || status.ID != binding.ReceiptID {
			return errors.Join(ErrProxyPolicyUnknown, err)
		}
		return ctx.Err()
	}
	if snapshot.PolicyTracked || snapshot.PolicyBinding != nil || receipt.Generation != "" {
		return ErrProxyPolicyUnknown
	}
	_, exists, err := a.readPolicyBinding(candidate)
	if err != nil || exists {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	if err := a.verifyUntrackedProxyHistory(); err != nil {
		return err
	}
	return ctx.Err()
}

func (a *ProxyTunnelAdapter) verifyUntrackedProxyHistory() error {
	tracked, err := a.trackedPolicyJournal()
	if err != nil {
		return errors.Join(ErrProxyPolicyUnknown, fmt.Errorf("inspect proxy policy journal: %w", err))
	}
	if tracked {
		return ErrProxyPolicyUnknown
	}
	return nil
}

func (a *ProxyTunnelAdapter) verifyProxyRestorationRuntime(ctx context.Context, snapshot proxySnapshot, candidate PolicyState) error {
	var err error
	a, err = a.xrayPreviousView(snapshot)
	if err != nil {
		return err
	}
	if err := a.verifyProxySnapshotRuntimeFiles(snapshot); err != nil {
		return err
	}
	if err := a.verifyHealthRuntime(ctx, snapshot.Policy); err != nil {
		return err
	}
	if err := a.verifyCandidateRemoved(ctx, snapshot.Policy, candidate); err != nil {
		return err
	}
	if a.scopedXray {
		if err := a.verifyScopedNodeInterface(ctx); err != nil {
			return err
		}
		if _, err := a.scopedRuntimeIdentity(); err != nil {
			return err
		}
	}
	if !a.Processes.Running(a.engineProcess()) || !a.Processes.Running(a.sidecarProcess()) {
		return ErrProxyPolicyUnknown
	}
	return ctx.Err()
}

func (a *ProxyTunnelAdapter) verifyProxySnapshotRuntimeFiles(s proxySnapshot) error {
	for _, file := range []struct {
		path   string
		data   []byte
		exists bool
	}{
		{a.engineConfigPath(), s.RuntimeEngine, s.RuntimeEngineExists},
		{a.sidecarConfigPath(), s.RuntimeSidecar, s.RuntimeSideExists},
		{a.transportPath(), s.Transport, s.TransportExists},
		{a.evidencePath(), s.Evidence, s.EvidenceExists},
		{a.nodeManifestPath(), s.NodeManifest, s.NodeManifestExists},
	} {
		if err := verifyRestoredFile(file.path, file.data, file.exists); err != nil {
			return err
		}
	}
	return nil
}
