package dataplane

import (
	"context"
	"errors"
	"os"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// An original cold snapshot and an untouched transaction do not authorize a
// Stop. Prove the current complete absence independently, then leave it alone.
// An issued/staged candidate must continue through its receipt-owned cleanup.
func (a *ProxyTunnelAdapter) verifyUnstagedColdXray(ctx context.Context, root string, s proxySnapshot, proof *proxyInactiveProof) (bool, error) {
	if a.ID() != "xray" || !a.xrayOperation || a.xrayCandidateMode != proxyXrayModeNode || a.xrayPreviousMode != proxyXrayModeCold {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, proxyInactiveBudget)
	defer cancel()
	// Only a snapshot-only transaction can use this path. A partial Stage may
	// already have prepared ownership receipts even without policy.staged.json.
	if _, err := os.Lstat(proxyPolicyReceiptPath(root)); !errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if _, err := a.readStagedPolicy(root); !errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if s.EngineID != "xray" || s.CandidateXrayMode != string(proxyXrayModeNode) || s.PreviousXrayMode != string(proxyXrayModeCold) ||
		s.ConfigDraft || s.PolicyExists || s.PolicyTracked || s.PolicyBinding != nil || s.PolicyWasActive ||
		s.EngineWasRunning || s.SidecarWasRunning || s.PackageWasRunning || s.RuntimeEngineExists || s.RuntimeSideExists ||
		s.TransportExists || s.EvidenceExists || s.NodeManifestExists || s.NodeInterfaceExists {
		return true, ErrProxyPolicyUnknown
	}
	identity, err := os.Lstat(root)
	if err != nil || !identity.IsDir() || identity.Mode()&os.ModeSymlink != 0 {
		return true, errors.Join(ErrProxyPolicyUnknown, err)
	}
	owned, err := ownedfs.Open(root)
	if err != nil {
		return true, errors.Join(ErrProxyPolicyUnknown, err)
	}
	defer owned.Close()
	images := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		currentIdentity, err := os.Lstat(root)
		if err != nil || !os.SameFile(identity, currentIdentity) {
			return errors.Join(ErrProxyPolicyUnknown, err)
		}
		entries, err := owned.ReadDir(2)
		if err != nil || len(entries) != 1 || entries[0].Name() != "snapshot.json" {
			return errors.Join(ErrProxyPolicyUnknown, err)
		}
		current, err := readProxySnapshot(root)
		if err != nil || !reflect.DeepEqual(current, s) {
			return errors.Join(ErrProxyPolicyUnknown, err)
		}
		if err := a.checkSnapshotSidecar(s); err != nil {
			return err
		}
		if err := a.checkXrayTransactionSnapshot(); err != nil {
			return err
		}
		boot, err := a.currentBootIdentity()
		if err != nil || boot == "" || boot != s.BootID {
			return errors.Join(ErrProxyPolicyUnknown, err)
		}
		if err := verifyRestoredFile(s.ConfigPath, s.Config, s.ConfigExisted); err != nil {
			return err
		}
		if err := a.verifyProxySnapshotRuntimeFiles(s); err != nil {
			return err
		}
		// Include interface/PID receipts and policy generations in the file
		// bookends, including after the final process/status observation.
		if err := a.inactiveFiles(ctx); err != nil {
			return err
		}
		return ctx.Err()
	}
	unchanged := func() error {
		if err := images(); err != nil {
			return err
		}
		if a.Processes.Running(a.engineProcess()) || a.Processes.Running(a.sidecarProcess()) {
			return ErrProxyPolicyUnknown
		}
		running, err := a.packageRuntimeRunning(ctx)
		if err != nil || running {
			return errors.Join(ErrProxyPolicyUnknown, err)
		}
		return images()
	}
	if err := unchanged(); err != nil {
		return true, err
	}
	if proof == nil {
		actual, err := proxyInactivePlatformProof()
		if err != nil {
			return true, errors.Join(ErrProxyRuntimeInactive, err)
		}
		proof = &actual
	}
	if err := a.verifyRuntimeInactive(ctx, *proof); err != nil {
		return true, err
	}
	return true, unchanged()
}
