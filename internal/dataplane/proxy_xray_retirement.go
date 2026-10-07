package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// Retirement has no staged B. Its private receipt names the original tracked
// A grant before teardown; neither cold intent nor kernel equality grants undo.
func (a *ProxyTunnelAdapter) isXrayRetirement() bool {
	return a != nil && a.ID() == "xray" && a.xraySnapshotHash != "" &&
		a.xrayCandidateMode == proxyXrayModeCold && a.xrayPreviousMode != proxyXrayModeCold
}

func (a *ProxyTunnelAdapter) rollbackPolicyState(root string) (PolicyState, error) {
	if !a.isXrayRetirement() {
		return a.readStagedPolicy(root)
	}
	snapshot, err := readProxySnapshot(root)
	if err != nil || a.verifyXrayTransactionSnapshot(snapshot) != nil || !snapshot.PolicyExists {
		return PolicyState{}, errors.Join(ErrProxyPolicyUnknown, err)
	}
	return snapshot.Policy, nil
}

func (a *ProxyTunnelAdapter) validateXrayRetirementReceipt(root string, receipt proxyPolicyReceipt) error {
	// The registered dispatcher may inspect private metadata without a bound
	// action. Mutating operation views must already be sealed cold retirement.
	if !a.isXrayRetirement() && (!a.xrayPlanDispatch || a.xrayOperation) {
		return ErrProxyPolicyUnknown
	}
	snapshot, err := readProxySnapshot(root)
	if err != nil || snapshot.CandidateXrayMode != string(proxyXrayModeCold) || snapshot.PolicyBinding == nil ||
		!snapshot.PolicyTracked || !snapshot.PolicyExists || !snapshot.PolicyWasActive ||
		!snapshot.EngineWasRunning || !snapshot.SidecarWasRunning || snapshot.PolicyBinding.Phase != "active" ||
		receipt.Boot == "" || receipt.Boot != snapshot.BootID || receipt.Generation != snapshot.PolicyBinding.Generation ||
		receipt.RetirementReceiptID == "" || snapshot.PolicyBinding.ReceiptID != receipt.RetirementReceiptID {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	if receipt.Phase != "prepared" && receipt.Phase != "restoring" && receipt.Phase != "restored" {
		return ErrProxyPolicyUnknown
	}
	if _, err := a.xraySnapshotPreviousMode(snapshot); err != nil {
		return err
	}
	data, err := json.Marshal(snapshot)
	defer clear(data)
	if err != nil || receipt.RetirementSnapshot != routeidentity.Hash(data) ||
		a.isXrayRetirement() && a.verifyXrayTransactionSnapshot(snapshot) != nil {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	return nil
}

func (a *ProxyTunnelAdapter) prepareXrayRetirement(ctx context.Context, root string) error {
	snapshot, err := readProxySnapshot(root)
	if err != nil || !a.isXrayRetirement() || snapshot.PolicyBinding == nil ||
		!snapshot.PolicyTracked || !snapshot.PolicyExists || !snapshot.PolicyWasActive ||
		!snapshot.EngineWasRunning || !snapshot.SidecarWasRunning {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	previous, err := a.xrayPreviousView(snapshot)
	if err != nil {
		return err
	}
	if err := previous.verifyUnstagedProxyRestoration(ctx, root, snapshot); err != nil {
		return err
	}
	if err := errors.Join(ctx.Err(), a.checkXrayTransactionSnapshot()); err != nil {
		return err
	}
	if err := previous.closeXrayRetirementActive(ctx, snapshot, *snapshot.PolicyBinding, true); err != nil {
		return err
	}
	if _, err := os.Lstat(proxyPolicyReceiptPath(root)); !errors.Is(err, os.ErrNotExist) {
		return ErrProxyPolicyUnknown
	}
	return writeProxyPolicyReceipt(root, proxyPolicyReceipt{Schema: 1, Engine: "xray", Boot: snapshot.BootID,
		Digest: proxyPolicyDigest(snapshot.Policy), Phase: "prepared", Generation: snapshot.PolicyBinding.Generation,
		RetirementSnapshot: a.xraySnapshotHash, RetirementReceiptID: snapshot.PolicyBinding.ReceiptID})
}

func (a *ProxyTunnelAdapter) originalXrayRetirementStatus(ctx context.Context, snapshot proxySnapshot, receipt proxyPolicyReceipt) (PolicyAdditionStatus, error) {
	boot, err := a.currentBootIdentity()
	if err != nil || boot != receipt.Boot || boot != snapshot.BootID || snapshot.PolicyBinding == nil ||
		receipt.Generation != snapshot.PolicyBinding.Generation || receipt.RetirementReceiptID != snapshot.PolicyBinding.ReceiptID {
		return PolicyAdditionStatus{}, errors.Join(ErrProxyPolicyUnknown, err)
	}
	root, err := a.policyGenerationRoot(receipt.Generation)
	if err != nil {
		return PolicyAdditionStatus{}, err
	}
	status, err := a.additionStatus(ctx, snapshot.Policy, root)
	if err != nil || status.Unknown || status.ID != receipt.RetirementReceiptID || !status.Complete && !status.Removed {
		return status, errors.Join(ErrProxyPolicyUnknown, err)
	}
	return status, a.checkXrayTransactionSnapshot()
}

func (a *ProxyTunnelAdapter) verifyXrayRetirementOriginalActive(ctx context.Context, snapshot proxySnapshot) error {
	binding, exists, err := a.readPolicyBinding(snapshot.Policy)
	if err != nil || !exists || snapshot.PolicyBinding == nil || binding != *snapshot.PolicyBinding || binding.Phase != "active" {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	policy, exists, err := a.loadPolicy()
	tracked, trackedErr := a.trackedPolicyJournal()
	if err != nil || trackedErr != nil || !exists || !tracked || !reflect.DeepEqual(policy, snapshot.Policy) {
		return errors.Join(ErrProxyPolicyUnknown, err, trackedErr)
	}
	if err := a.verifyCommittedReceipt(ctx, policy); err != nil {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	if err := a.verifyProxyRestorationRuntime(ctx, snapshot, snapshot.Policy); err != nil {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	return a.closeXrayRetirementActive(ctx, snapshot, *snapshot.PolicyBinding, true)
}

// No process, kernel, LAN or boot callbacks occur after the final metadata
// reads. A matching earlier readback cannot grant ownership of a later writer.
func (a *ProxyTunnelAdapter) retirementClosingView(ctx context.Context, snapshot proxySnapshot) (*ProxyTunnelAdapter, error) {
	boot, err := a.currentBootIdentity()
	if err != nil || boot == "" || boot != snapshot.BootID || ctx.Err() != nil {
		return nil, errors.Join(ErrProxyPolicyUnknown, err, ctx.Err())
	}
	view := *a
	view.bootIdentity = func() (string, error) { return boot, nil }
	return &view, nil
}

func (a *ProxyTunnelAdapter) closeXrayRetirementReceipt(snapshot proxySnapshot, expected proxyPolicyReceipt) error {
	current, err := a.readCandidatePolicyReceipt(a.xraySnapshotRoot, snapshot.Policy)
	if err != nil || current != expected {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	// The closing ledger read uses the boot already verified by the caller;
	// it must not reopen an external callback after ownership was checked.
	view := *a
	view.bootIdentity = func() (string, error) { return expected.Boot, nil }
	status, err := view.originalXrayRetirementStatus(context.Background(), snapshot, expected)
	if err != nil || (expected.Phase == "restoring" || expected.RestorationGeneration != "") && !status.Removed {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	return a.checkXrayTransactionSnapshot()
}

func (a *ProxyTunnelAdapter) closeXrayRetirementActive(ctx context.Context, snapshot proxySnapshot, expected proxyPolicyBinding, requireJournal bool) error {
	runtime, err := a.captureXrayRetirementRuntime()
	if err != nil {
		return err
	}
	processes := []ProcessSpec{a.engineProcess(), a.sidecarProcess()}
	identities := make([]string, len(processes))
	for i, spec := range processes {
		if spec.RouteProof {
			identities[i], err = a.verifyNodeProcess(spec, "")
			if err != nil || identities[i] == "" {
				return errors.Join(ErrProxyPolicyUnknown, err)
			}
		}
	}
	view, err := a.retirementClosingView(ctx, snapshot)
	if err != nil {
		return err
	}
	// A process may exit while boot is sampled without deleting its passport.
	// Close Running after boot, then repeat the stronger live birth proof so
	// a successful Running callback cannot hide an exit of a proved process.
	// Only callback-free binding/ledger/file checks follow; do not reopen boot.
	if !view.Processes.Running(processes[0]) || !view.Processes.Running(processes[1]) {
		return ErrProxyPolicyUnknown
	}
	for i, spec := range processes {
		if spec.RouteProof {
			identity, err := view.verifyNodeProcess(spec, "")
			if err != nil || identity != identities[i] {
				return errors.Join(ErrProxyPolicyUnknown, err)
			}
		}
	}
	binding, exists, err := view.readPolicyBinding(snapshot.Policy)
	if err != nil || !exists || binding != expected {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	if requireJournal {
		policy, exists, err := view.loadPolicy()
		tracked, trackedErr := view.trackedPolicyJournal()
		if err != nil || trackedErr != nil || !exists || !tracked || !reflect.DeepEqual(policy, snapshot.Policy) {
			return errors.Join(ErrProxyPolicyUnknown, err, trackedErr)
		}
	}
	generation, err := view.policyGenerationRoot(expected.Generation)
	if err != nil {
		return err
	}
	status, err := view.additionStatus(ctx, snapshot.Policy, generation)
	if err != nil || !status.Complete || status.Unknown || expected.ReceiptID != "" && status.ID != expected.ReceiptID {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	return errors.Join(view.verifyProxySnapshotRuntimeFiles(snapshot), view.checkXrayTransactionSnapshot(), closeXrayRetirementRuntime(runtime), ctx.Err())
}

type xrayRetirementRuntimeImage struct {
	path   string
	data   []byte
	exists bool
}

// Pin the new runtime's current lease and process passports across readback;
// the old captured ifindex is intentionally not replayed as new authority.
func (a *ProxyTunnelAdapter) captureXrayRetirementRuntime() ([]xrayRetirementRuntimeImage, error) {
	root, err := ownedfs.Open(a.runtimeRoot())
	if err != nil {
		return nil, errors.Join(ErrProxyPolicyUnknown, err)
	}
	defer root.Close()
	paths := []string{a.nodeInterfacePath(), a.engineProcess().PIDPath, a.sidecarProcess().PIDPath,
		a.engineProcess().PIDPath + routeidentity.ReceiptSuffix, a.sidecarProcess().PIDPath + routeidentity.ReceiptSuffix}
	limits := []int64{4096, 64, 64, 128 << 10, 128 << 10}
	var images []xrayRetirementRuntimeImage
	for i, path := range paths {
		image, _, err := readProxyXrayImage(root, filepath.Base(path), limits[i])
		if err != nil || i == 0 && (a.scopedXray && !image.exists || !a.scopedXray && image.exists) {
			return nil, errors.Join(ErrProxyPolicyUnknown, err)
		}
		images = append(images, xrayRetirementRuntimeImage{path: path, data: image.data, exists: image.exists})
	}
	return images, nil
}

func closeXrayRetirementRuntime(images []xrayRetirementRuntimeImage) error {
	for _, image := range images {
		if err := verifyRestoredFile(image.path, image.data, image.exists); err != nil {
			return errors.Join(ErrProxyPolicyUnknown, err)
		}
	}
	return nil
}

func (a *ProxyTunnelAdapter) verifyXrayRetirementPriorBinding(snapshot proxySnapshot) error {
	binding, exists, err := a.readPolicyBinding(snapshot.Policy)
	if err != nil || exists && (snapshot.PolicyBinding == nil || binding.Generation != snapshot.PolicyBinding.Generation ||
		binding.ReceiptID != snapshot.PolicyBinding.ReceiptID || binding.Phase != "removed") {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	policy, present, err := a.loadPolicy()
	tracked, trackedErr := a.trackedPolicyJournal()
	if err != nil || trackedErr != nil || present && (!tracked || !reflect.DeepEqual(policy, snapshot.Policy)) {
		return errors.Join(ErrProxyPolicyUnknown, err, trackedErr)
	}
	return nil
}

func (a *ProxyTunnelAdapter) verifyXrayRetirementMetadata(snapshot proxySnapshot) error {
	if err := a.verifyXrayRetirementPriorBinding(snapshot); err != nil {
		return err
	}
	// A surviving image must be the captured A; a partial teardown cannot
	// authorize a foreign image. Missing images are never filled from argv.
	for _, file := range []struct {
		path   string
		data   []byte
		exists bool
	}{
		{a.engineConfigPath(), snapshot.RuntimeEngine, snapshot.RuntimeEngineExists},
		{a.sidecarConfigPath(), snapshot.RuntimeSidecar, snapshot.RuntimeSideExists},
		{a.nodeManifestPath(), snapshot.NodeManifest, snapshot.NodeManifestExists},
		{a.transportPath(), snapshot.Transport, snapshot.TransportExists},
		{a.evidencePath(), snapshot.Evidence, snapshot.EvidenceExists},
		{a.nodeInterfacePath(), snapshot.NodeInterface, snapshot.NodeInterfaceExists},
	} {
		if _, err := os.Lstat(file.path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := verifyRestoredFile(file.path, file.data, file.exists); err != nil {
			return errors.Join(ErrProxyPolicyUnknown, err)
		}
	}
	// Stop and Start may discard stale PID/passport markers. Retirement's
	// removed ledger grants no authority over a surviving process identity.
	for _, path := range []string{a.forwardingPath(), a.engineProcess().PIDPath, a.sidecarProcess().PIDPath,
		a.engineProcess().PIDPath + routeidentity.ReceiptSuffix, a.sidecarProcess().PIDPath + routeidentity.ReceiptSuffix} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return ErrProxyPolicyUnknown
		}
	}
	return a.checkXrayTransactionSnapshot()
}

func (a *ProxyTunnelAdapter) verifyXrayRetirementPreRestoration(ctx context.Context, snapshot proxySnapshot, receipt proxyPolicyReceipt) error {
	status, err := a.originalXrayRetirementStatus(ctx, snapshot, receipt)
	if err != nil || !status.Removed || receipt.RestorationGeneration != "" {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	if err := a.verifyXrayRetirementMetadata(snapshot); err != nil {
		return err
	}
	if err := a.verifyXrayInterfaceAbsent(ctx); err != nil {
		return err
	}
	if err := inspectPolicyDefaults(ctx, a.Runner, a.ip(), snapshot.Policy, false); err != nil {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	if err := verifyPolicyPrecedence(ctx, a.Runner, a.ip(), snapshot.Policy, true); err != nil {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	if err := a.preflightForwarding(ctx, snapshot.Policy); err != nil {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	empty := PolicyState{Interface: snapshot.Policy.Interface, Table: snapshot.Policy.Table, PriorityBase: snapshot.Policy.PriorityBase,
		RuleLayout: snapshot.Policy.RuleLayout, SharedPriorityBase: snapshot.Policy.SharedPriorityBase}
	if err := a.verifyCandidateRemoved(ctx, empty, snapshot.Policy); err != nil {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	// LAN/firewall readbacks can outlive the first interface observation.
	// Close actual TUN absence before the final callback-free metadata gate.
	if err := a.verifyXrayInterfaceAbsent(ctx); err != nil {
		return err
	}
	view, err := a.retirementClosingView(ctx, snapshot)
	if err != nil {
		return err
	}
	status, err = view.originalXrayRetirementStatus(ctx, snapshot, receipt)
	if err != nil || !status.Removed {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	return errors.Join(view.verifyXrayRetirementMetadata(snapshot), view.closeXrayRetirementReceipt(snapshot, receipt), ctx.Err())
}

func (a *ProxyTunnelAdapter) rollbackXrayRetirement(ctx context.Context, snapshot proxySnapshot, root string) error {
	previous, err := a.xrayPreviousView(snapshot)
	if err != nil {
		return err
	}
	receipt, err := previous.readCandidatePolicyReceipt(root, snapshot.Policy)
	if err != nil {
		return err
	}
	status, err := previous.originalXrayRetirementStatus(ctx, snapshot, receipt)
	if err != nil {
		return err
	}
	if status.Complete {
		if receipt.RestorationGeneration != "" || receipt.Phase != "prepared" && receipt.Phase != "restored" {
			return ErrProxyPolicyUnknown
		}
		if err := previous.verifyXrayRetirementOriginalActive(ctx, snapshot); err != nil {
			return err
		}
		return previous.finishProxyRollback(ctx, snapshot, root, true)
	}
	if receipt.Phase == "restored" {
		runtime, err := previous.captureXrayRetirementRuntime()
		if err != nil {
			return err
		}
		if err := previous.verifyXrayRetirementVerificationGrant(ctx, snapshot, root); err != nil {
			return err
		}
		if err := previous.verifyProxyRestorationRuntime(ctx, snapshot, snapshot.Policy); err != nil {
			return err
		}
		return errors.Join(previous.verifyXrayRetirementVerificationGrant(ctx, snapshot, root), previous.closeXrayRetirementReceipt(snapshot, receipt),
			closeXrayRetirementRuntime(runtime), ctx.Err())
	}
	if receipt.Phase == "restoring" && receipt.RestorationGeneration != "" {
		complete, err := previous.resumeProxyPolicyRestoration(ctx, root, snapshot.Policy, snapshot, receipt)
		if err != nil || !complete {
			return errors.Join(ErrProxyPolicyUnknown, err)
		}
		return previous.finishProxyRollback(ctx, snapshot, root, true)
	}
	if receipt.Phase != "prepared" && receipt.Phase != "restoring" {
		return ErrProxyPolicyUnknown
	}
	if err := previous.verifyXrayRetirementPreRestoration(ctx, snapshot, receipt); err != nil {
		return err
	}
	receipt.Phase = "restoring"
	receipt.Checksum = ""
	canonical, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	receipt.Checksum = routeidentity.Hash(canonical)
	clear(canonical)
	if err := writeProxyPolicyReceipt(root, receipt); err != nil {
		return err
	}
	// Even a cut during owned process cleanup retains restoring before Start.
	for _, spec := range []ProcessSpec{previous.sidecarProcess(), previous.engineProcess()} {
		if err := previous.Processes.Stop(ctx, spec); err != nil {
			return err
		}
		if err := errors.Join(previous.verifyXrayRetirementMetadata(snapshot), previous.closeXrayRetirementReceipt(snapshot, receipt), ctx.Err()); err != nil {
			return err
		}
	}
	if err := previous.verifyXrayRetirementPreRestoration(ctx, snapshot, receipt); err != nil {
		return err
	}
	return previous.restoreProxySnapshot(ctx, snapshot, root, true)
}

func (a *ProxyTunnelAdapter) verifyXrayRetirementVerificationGrant(ctx context.Context, snapshot proxySnapshot, root string) error {
	receipt, err := a.readCandidatePolicyReceipt(root, snapshot.Policy)
	if err != nil || receipt.Phase != "prepared" && receipt.Phase != "restored" {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	status, err := a.originalXrayRetirementStatus(ctx, snapshot, receipt)
	if err != nil {
		return err
	}
	if receipt.RestorationGeneration == "" {
		if !status.Complete {
			return ErrProxyPolicyUnknown
		}
		if err := a.verifyXrayRetirementOriginalActive(ctx, snapshot); err != nil {
			return err
		}
		return errors.Join(a.closeXrayRetirementReceipt(snapshot, receipt), ctx.Err())
	}
	if !status.Removed || receipt.Phase != "restored" {
		return ErrProxyPolicyUnknown
	}
	binding, exists, err := a.readPolicyBinding(snapshot.Policy)
	if err != nil || !exists || binding.Generation != receipt.RestorationGeneration || binding.Phase != "active" {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	if err := a.closeXrayRetirementActive(ctx, snapshot, binding, true); err != nil {
		return err
	}
	return errors.Join(a.closeXrayRetirementReceipt(snapshot, receipt), ctx.Err())
}
