package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

func (a *ProxyTunnelAdapter) consumeXrayCandidateInterface(ctx context.Context) error {
	data, err := readBoundedSidecar(a.nodeInterfacePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || len(data) > 4096 {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	defer clear(data)
	var lease nodeInterfaceLease
	config, err := readBoundedProxyConfig(a.engineConfigPath())
	if err != nil {
		return err
	}
	defer clear(config)
	boot, bootErr := a.currentBootIdentity()
	if decodeProxyXrayModeJSON(data, &lease) != nil || bootErr != nil || lease.Schema != 1 || lease.Boot != boot || lease.Interface != a.Interface ||
		lease.Index < 1 || lease.ConfigHash != routeidentity.Hash(config) {
		return errors.Join(ErrProxyPolicyUnknown, bootErr)
	}
	return os.Remove(a.nodeInterfacePath())
}

func (a *ProxyTunnelAdapter) verifyXrayInterfaceAbsent(ctx context.Context) error {
	if _, err := a.scopedInterfaceIndex(ctx); !errors.Is(err, errNodeInterfaceAbsent) {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	return ctx.Err()
}

func (a *ProxyTunnelAdapter) consumeXrayNodeHistory(snapshot proxySnapshot) error {
	if !snapshot.NodeManifestExists || verifyRestoredFile(a.nodeManifestPath(), snapshot.NodeManifest, true) != nil {
		return ErrProxyPolicyUnknown
	}
	if _, err := os.Lstat(a.nodeInterfacePath()); err == nil {
		if !snapshot.NodeInterfaceExists || verifyRestoredFile(a.nodeInterfacePath(), snapshot.NodeInterface, true) != nil {
			return ErrProxyPolicyUnknown
		}
		if err := os.Remove(a.nodeInterfacePath()); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Remove(a.nodeManifestPath())
}

func (a *ProxyTunnelAdapter) dispatchXrayPlan(plan Plan, root string, snapshotRequired bool) (*ProxyTunnelAdapter, Plan, error) {
	plan.Routes = cloneNetworkPolicyRoutes(plan.Routes)
	plan.LAN = CloneLANPolicyRuntime(plan.LAN)
	plan.EngineDrafts = append([]string(nil), plan.EngineDrafts...)
	plan.RetiringAdapters = append([]string(nil), plan.RetiringAdapters...)
	mode, err := a.xrayPlanMode(plan)
	if err != nil {
		return nil, Plan{}, err
	}
	view, err := a.xrayModeView(mode)
	if err != nil {
		return nil, Plan{}, err
	}
	view.xrayOperation = true
	view.xrayCandidateMode = mode
	if snapshotRequired {
		identity, identityErr := os.Lstat(root)
		if identityErr != nil || !identity.IsDir() || identity.Mode()&os.ModeSymlink != 0 {
			return nil, Plan{}, errors.Join(ErrProxyPolicyUnknown, identityErr)
		}
		snapshot, err := readProxySnapshot(root)
		if err != nil || snapshot.CandidateXrayMode != "" && snapshot.CandidateXrayMode != string(mode) {
			return nil, Plan{}, errors.Join(ErrProxyPolicyUnknown, err)
		}
		view.xrayPreviousMode, err = a.xraySnapshotPreviousMode(snapshot)
		if err != nil {
			return nil, Plan{}, err
		}
		closing, closingErr := os.Lstat(root)
		if closingErr != nil || !closing.IsDir() || closing.Mode()&os.ModeSymlink != 0 || !os.SameFile(identity, closing) {
			return nil, Plan{}, errors.Join(ErrProxyPolicyUnknown, closingErr)
		}
		data, err := json.Marshal(snapshot)
		if err != nil {
			return nil, Plan{}, err
		}
		view.xraySnapshotRoot, view.xraySnapshotHash, view.xraySnapshotOwner = root, routeidentity.Hash(data), identity
		clear(data)
	}
	return view, plan, nil
}

func (a *ProxyTunnelAdapter) dispatchCandidateXrayPlan(plan Plan, root string, snapshotRequired bool) (*ProxyTunnelAdapter, Plan, error) {
	view, frozen, err := a.dispatchXrayPlan(plan, root, snapshotRequired)
	if err != nil {
		return nil, Plan{}, err
	}
	if view.xrayCandidateMode == proxyXrayModeCold {
		return nil, Plan{}, proxyXrayModeError()
	}
	return view, frozen, nil
}

func (a *ProxyTunnelAdapter) dispatchCurrentXrayPlan(ctx context.Context, plan Plan) (*ProxyTunnelAdapter, Plan, error) {
	view, frozen, err := a.dispatchCandidateXrayPlan(plan, "", false)
	if err != nil {
		return nil, Plan{}, err
	}
	current, err := a.currentXrayRuntimeMode(ctx)
	if err != nil || current == proxyXrayModeCold || (current == proxyXrayModeNode) != view.scopedXray {
		return nil, Plan{}, errors.Join(ErrProxyPolicyUnknown, err)
	}
	return view, frozen, nil
}

func (a *ProxyTunnelAdapter) xrayPreviousView(snapshot proxySnapshot) (*ProxyTunnelAdapter, error) {
	if err := a.verifyXrayTransactionSnapshot(snapshot); err != nil {
		return nil, err
	}
	if !a.xrayOperation {
		return a, nil
	}
	mode, err := a.xraySnapshotPreviousMode(snapshot)
	if err != nil {
		return nil, err
	}
	if a.xrayPreviousMode != "" && mode != a.xrayPreviousMode {
		return nil, proxyXrayModeError()
	}
	view, err := a.xrayModeView(mode)
	if err != nil {
		return nil, err
	}
	view.xrayOperation = false
	return view, nil
}

func (a *ProxyTunnelAdapter) verifyXrayTransactionSnapshot(snapshot proxySnapshot) error {
	if a.xraySnapshotHash == "" {
		return nil
	}
	if err := a.verifyXraySnapshotRoot(); err != nil {
		return err
	}
	mode, err := a.xraySnapshotPreviousMode(snapshot)
	data, marshalErr := json.Marshal(snapshot)
	defer clear(data)
	if err != nil || marshalErr != nil || mode != a.xrayPreviousMode ||
		snapshot.CandidateXrayMode != "" && snapshot.CandidateXrayMode != string(a.xrayCandidateMode) || routeidentity.Hash(data) != a.xraySnapshotHash {
		return errors.Join(ErrProxyPolicyUnknown, err, marshalErr)
	}
	return a.verifyXraySnapshotRoot()
}

func (a *ProxyTunnelAdapter) checkXrayTransactionSnapshot() error {
	if a.xraySnapshotHash == "" {
		return nil
	}
	if err := a.verifyXraySnapshotRoot(); err != nil {
		return err
	}
	snapshot, err := readProxySnapshot(a.xraySnapshotRoot)
	if err != nil {
		return err
	}
	return a.verifyXrayTransactionSnapshot(snapshot)
}

func (a *ProxyTunnelAdapter) verifyXraySnapshotRoot() error {
	current, err := os.Lstat(a.xraySnapshotRoot)
	if err != nil || a.xraySnapshotOwner == nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(a.xraySnapshotOwner, current) {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	return nil
}
