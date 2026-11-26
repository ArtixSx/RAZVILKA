package dataplane

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"time"
)

// An in-use private identity grants no second interface. A reviewed network
// candidate may instead probe its exact, still-committed runtime on the existing
// interface. A changed peer, endpoint, PSK or any other profile byte is refused.
func (a *WARPWireGuardAdapter) verifyOwnedWGNetworkProbe(ctx context.Context, root string, profile []byte) error {
	if err := checkWGNetworkReview(ctx); err != nil {
		return err
	}
	if err := a.checkWGPolicyOperation(); err != nil {
		return err
	}
	snapshot, err := readWarpWGSnapshot(root)
	if err != nil {
		return err
	}
	if !snapshot.StateExisted || !snapshot.RuntimeExisted || !snapshot.InterfaceWasActive || snapshot.State.WireGuardEndpoint == nil || !bytes.Equal(profile, snapshot.RuntimeConfig) || a.validWGSnapshotPolicyReference(snapshot) != nil {
		return ErrWGCanaryIdentityInUse
	}
	if err := a.verifyNamedProfile(ctx, snapshot); err != nil {
		return err
	}
	runtime, exists, err := readWARPCleanupFile(a.RuntimeConfigPath, 256<<10)
	if err != nil || !exists || !bytes.Equal(runtime, snapshot.RuntimeConfig) {
		return errors.Join(err, ErrWGCanaryIdentityInUse)
	}
	state, owned, err := a.deactivationOwnership(ctx)
	if err != nil || !owned || policyAdditionHash(state) != policyAdditionHash(snapshot.State) {
		return errors.Join(err, ErrWGCanaryIdentityInUse)
	}
	ref, err := a.committedWGPolicyReference(state)
	if err != nil || ref.ID != snapshot.PolicyGeneration.ID || ref.Checksum != snapshot.PolicyGeneration.Checksum {
		return errors.Join(err, ErrPolicyAdditionUnknown)
	}
	boot, err := a.wgPolicyBoot()
	if err != nil || boot != ref.Boot {
		return errors.Join(err, ErrPolicyAdditionUnknown)
	}
	status, err := a.inspectWGPolicyReference(ctx, ref, "")
	if err != nil || !status.Complete || status.Removed || status.Unknown || status.Promoted {
		return errors.Join(err, ErrPolicyAdditionUnknown)
	}
	active, err := a.deactivationInterfaceActive(ctx)
	if err != nil || !active {
		return errors.Join(err, ErrWGCanaryIdentityInUse)
	}
	if err := a.verifyWGEndpoint(ctx, state.WireGuardEndpoint, ref.FrozenLAN); err != nil {
		return err
	}
	if err := a.verifyOwnedWGNetworkPeer(ctx, profile); err != nil {
		return err
	}
	if err := a.revalidateWGEndpoint(ctx, state.WireGuardEndpoint); err != nil {
		return err
	}
	if err := verifyPolicyEvidence(ctx, a.Runner, a.ip(), state); err != nil {
		return err
	}
	if state.NetworkPolicyGeneration != "" {
		if err := a.verifyWGNetworkEffectPresence(ctx, ref, 1); err != nil {
			return err
		}
	}
	return a.inspectWGProbeIdentity(ctx, profile, a.interfaceName())
}

func (a *WARPWireGuardAdapter) probeOwnedWGNetworkCandidate(ctx context.Context, plan RoutePlan, root string, profile []byte, sources []netip.Addr) (retErr error) {
	if a.ID() != "wireguard" && a.ID() != "amneziawg" {
		return ErrWGCanaryIdentityInUse
	}
	if err := a.verifyOwnedWGNetworkProbe(ctx, root, profile); err != nil {
		return err
	}
	probeAdapter := *a
	probeAdapter.Table, probeAdapter.PriorityBase = 219, 18050
	probeAdapter.FallbackPorts = []int{}
	if err := probeAdapter.ensureCanaryPolicyFree(ctx); err != nil {
		return err
	}
	var installed []netip.Addr
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
		defer cancel()
		var cleanupErr error
		for i := len(installed) - 1; i >= 0; i-- {
			cleanupErr = errors.Join(cleanupErr, probeAdapter.cleanupCanaryPolicy(cleanup, installed[i]))
		}
		retErr = errors.Join(retErr, cleanupErr)
		if cleanupErr == nil {
			retErr = errors.Join(retErr, a.verifyOwnedWGNetworkProbe(ctx, root, profile))
		}
	}()
	for _, source := range sources {
		if err := probeAdapter.installCanaryPolicy(ctx, source); err != nil {
			return err
		}
		installed = append(installed, source)
	}
	tcp := a.CanaryProbe
	if tcp == nil {
		tcp = sourceBoundAWGProbe
	}
	udp := sourceBoundWGNetworkUDPProbe
	if a.networkUDPProbe != nil {
		udp = a.networkUDPProbe
	}
	ctx = context.WithValue(ctx, wgSocketInterfaceKey{}, a.interfaceName())
	return probeAdapter.probeWGNetworkFamilies(ctx, plan, filepath.Clean(root), sources, tcp, udp)
}
