package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// Private operation context, installed by the actual owner before issuance.
// Manager matches its immutable execution record before invoking this readback.
// No public DTO, saved callback, or supplied path can create this capability.
type networkPolicyTransitReadbackMode string

const (
	networkPolicyTransitPrepared networkPolicyTransitReadbackMode = "prepared"
	networkPolicyTransitRemoved  networkPolicyTransitReadbackMode = "removed"
	networkPolicyTransitUnused   networkPolicyTransitReadbackMode = "unused"
)

type networkPolicyTransitReadback func(context.Context, NodeTransitSpec, string, string, networkPolicyTransitReadbackMode) error
type networkPolicyTransitReadbackKey struct{}

// nodeTransitRuntimeFor supplies actual read-only owner checks to Manager's
// independently reconstructed lease. Manager must separately bind PlanID and
// PlanDigest to its original execution and supply its existing-record register
// callback; a nil register here intentionally grants no Apply/Remove authority.
func (a *ProxyTunnelAdapter) nodeTransitRuntimeFor(ctx context.Context, spec NodeTransitSpec) (nodeTransitRuntime, error) {
	if ctx == nil || a == nil || !a.scopedXray || !a.nodeRouterVerifier || a.Runner == nil || a.Processes == nil ||
		spec.Engine != a.ID() || spec.Interface != a.Interface || spec.Table != a.Table || validateNodeTransitSpec(spec) != nil ||
		!filepath.IsAbs(a.StateRoot) || filepath.Clean(a.StateRoot) != a.StateRoot || filepath.Base(a.StateRoot) != a.ID() {
		return nodeTransitRuntime{}, ErrNodeTransitUnavailable
	}
	prefix, err := netip.ParsePrefix(a.TunnelCIDR)
	if err != nil || prefix.Addr() != spec.Source {
		return nodeTransitRuntime{}, ErrNodeTransitUnavailable
	}
	for _, process := range []ProcessSpec{a.engineProcess(), a.sidecarProcess()} {
		if err := validateProcessSpec(process); err != nil {
			return nodeTransitRuntime{}, err
		}
	}
	manifest, err := a.readNodeManifest(a.nodeManifestPath())
	if err != nil || manifest.NetworkProfile != spec.NetworkProfile {
		return nodeTransitRuntime{}, errors.Join(ErrNodeTransitUnavailable, err)
	}
	raw, _ := json.Marshal(manifest)
	manifestHash := routeidentity.Hash(raw)
	state, exists, err := a.loadPolicy()
	if err != nil || !exists {
		return nodeTransitRuntime{}, errors.Join(ErrNodeTransitUnavailable, err)
	}
	stateHash := proxyPolicyDigest(state)
	guard := func(c context.Context, current NodeTransitSpec) error {
		if c == nil || c.Err() != nil || current != spec {
			return ErrNodeTransitUnavailable
		}
		boot, err := a.currentBootIdentity()
		if err != nil || boot != spec.BootID {
			return ErrNodeTransitUnavailable
		}
		if err := a.verifyScopedNodeInterface(c); err != nil {
			return err
		}
		identity, err := a.scopedRuntimeIdentity()
		if err != nil || identity != spec.RuntimeID {
			return ErrNodeTransitUnavailable
		}
		actual, err := a.readNodeManifest(a.nodeManifestPath())
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(actual)
		if routeidentity.Hash(raw) != manifestHash {
			return ErrNodeTransitUnavailable
		}
		currentState, exists, err := a.loadPolicy()
		if err != nil || !exists || proxyPolicyDigest(currentState) != stateHash {
			return ErrNodeTransitUnavailable
		}
		if err := a.nodeTransitCurrentGeneration(c, state, spec); err != nil {
			return err
		}
		request := nodeRouterHTTPSRequest{Interface: spec.Interface, IfIndex: spec.IfIndex, Source: spec.Source}
		return nodeRouterAssignedSource(c, request, nodeRouterHTTPSOptions{})
	}
	if err := guard(ctx, spec); err != nil {
		return nodeTransitRuntime{}, err
	}
	return nodeTransitRuntime{runner: a.Runner, ip: a.ip(), guard: guard, preflight: guard, beforeDelete: guard}, nil
}

func (a *ProxyTunnelAdapter) nodeTransitCurrentGeneration(ctx context.Context, state PolicyState, spec NodeTransitSpec) error {
	binding, exists, bindingErr := a.readPolicyBinding(state)
	if bindingErr == nil && exists && binding.Phase == "active" && binding.Generation == spec.PolicyGeneration {
		generation, err := a.nodeRouterPolicyGeneration(ctx, state, "")
		if err != nil || generation != spec.PolicyGeneration {
			return errors.Join(ErrNodeTransitUnavailable, err)
		}
		return nil
	}
	// This is a fixed local path derived from a validated execution ID, never a
	// cleanup root supplied by a DTO. A candidate may coexist with an old binding.
	candidate := filepath.Join(filepath.Dir(a.StateRoot), "transactions", spec.PlanID, a.ID())
	generation, err := a.nodeRouterPolicyGeneration(ctx, state, candidate)
	if err != nil || generation != spec.PolicyGeneration {
		return errors.Join(ErrNodeTransitUnavailable, bindingErr, err)
	}
	return ctx.Err()
}

// Read the existing anchored document and permanent marker without the common
// opener, which may create a lock. The same trusted compiler/state loaders still
// validate checksum, boot, root and commands; no second receipt grammar exists.
func nodeTransitReadReceipt(ctx context.Context, path string, boot func() (string, error), load func(*policyAdditionSession) error) (PolicyAdditionStatus, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || boot == nil {
		return PolicyAdditionStatus{}, ErrPolicyAdditionReceipt
	}
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && before.Mode().Perm()&0077 != 0 {
		return PolicyAdditionStatus{}, ErrPolicyAdditionReceipt
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return PolicyAdditionStatus{}, err
	}
	defer root.Close()
	markerInfo, err := root.Stat(policyAdditionLock)
	marker, markerErr := root.ReadLimited(policyAdditionLock, int64(len(policyAdditionMarker)+1))
	documentInfo, documentErr := root.Stat(policyAdditionFile)
	if err != nil || !validCloudflareScanLockFile(markerInfo) || markerErr != nil || string(marker) != policyAdditionMarker ||
		documentErr != nil || !documentInfo.Mode().IsRegular() || documentInfo.Size() > policyAdditionMaxBytes ||
		runtime.GOOS != "windows" && documentInfo.Mode().Perm()&0077 != 0 {
		return PolicyAdditionStatus{}, ErrPolicyAdditionReceipt
	}
	document, err := root.ReadLimited(policyAdditionFile, policyAdditionMaxBytes)
	if err != nil {
		return PolicyAdditionStatus{}, err
	}
	s := &policyAdditionSession{root: root, path: path, options: policyAdditionOptions{boot: boot}}
	if err := load(s); err != nil {
		return PolicyAdditionStatus{}, err
	}
	loaded, err := json.Marshal(s.doc)
	var compact bytes.Buffer
	if err != nil || json.Compact(&compact, document) != nil || !bytes.Equal(compact.Bytes(), loaded) {
		return PolicyAdditionStatus{}, ErrPolicyAdditionReceipt
	}
	closingRoot, err := os.Lstat(path)
	closingMarkerInfo, markerInfoErr := root.Stat(policyAdditionLock)
	closingMarker, markerErr := root.ReadLimited(policyAdditionLock, int64(len(policyAdditionMarker)+1))
	closingDocumentInfo, documentInfoErr := root.Stat(policyAdditionFile)
	closingDocument, documentErr := root.ReadLimited(policyAdditionFile, policyAdditionMaxBytes)
	if err != nil || !closingRoot.IsDir() || closingRoot.Mode()&os.ModeSymlink != 0 ||
		runtime.GOOS != "windows" && closingRoot.Mode().Perm()&0077 != 0 || !os.SameFile(before, closingRoot) ||
		markerInfoErr != nil || !os.SameFile(markerInfo, closingMarkerInfo) ||
		!validCloudflareScanLockFile(closingMarkerInfo) || markerErr != nil || string(closingMarker) != policyAdditionMarker ||
		documentInfoErr != nil || !closingDocumentInfo.Mode().IsRegular() || closingDocumentInfo.Size() > policyAdditionMaxBytes ||
		runtime.GOOS != "windows" && closingDocumentInfo.Mode().Perm()&0077 != 0 ||
		!os.SameFile(documentInfo, closingDocumentInfo) || documentErr != nil ||
		routeidentity.Hash(document) != routeidentity.Hash(closingDocument) || ctx.Err() != nil {
		return PolicyAdditionStatus{}, ErrPolicyAdditionReceipt
	}
	return s.status(), nil
}

func nodeTransitReadAddition(ctx context.Context, state PolicyState, path string, boot func() (string, error)) (PolicyAdditionStatus, error) {
	return nodeTransitReadReceipt(ctx, path, boot, func(s *policyAdditionSession) error {
		s.state = state
		return s.load(ctx)
	})
}

func nodeTransitReadEffects(ctx context.Context, plan PolicyEffectPlan, path string, boot func() (string, error)) (PolicyAdditionStatus, error) {
	plan, hash, err := copyPolicyEffectPlan(plan)
	if err != nil {
		return PolicyAdditionStatus{}, err
	}
	return nodeTransitReadReceipt(ctx, path, boot, func(s *policyAdditionSession) error {
		return (&policyEffectSession{policyAdditionSession: s, plan: plan, hash: hash}).load(ctx)
	})
}

type nodeRouterTransitReadback struct {
	spec   NodeTransitSpec
	root   string
	info   os.FileInfo
	lease  *nodeTransitLease
	unused *nodeTransitBeforeEffectsError
	owner  func(context.Context) error
}

func (b *nodeRouterTransitReadback) readback(ctx context.Context, spec NodeTransitSpec, root, digest string, mode networkPolicyTransitReadbackMode) error {
	if ctx == nil || ctx.Err() != nil || b == nil || b.lease == nil || b.info == nil || b.owner == nil ||
		spec != b.spec || root != b.root || digest != b.lease.digest || b.lease.spec != spec || b.lease.root != root {
		return ErrNodeTransitUnavailable
	}
	// Independent readback must not reenter Manager's cleanup/register guard.
	// This mirror has no registration, preflight or deletion callback and no
	// live unused proof; it is used only for identity, Inspect and presence.
	observer := &nodeTransitLease{spec: spec, plan: b.lease.plan, digest: digest, root: root, options: b.lease.options,
		runtime: nodeTransitRuntime{runner: b.lease.runtime.runner, ip: b.lease.runtime.ip,
			guard: func(c context.Context, current NodeTransitSpec) error {
				if current != b.spec {
					return ErrNodeTransitUnavailable
				}
				return b.owner(c)
			}}}
	check := func() error {
		if err := b.owner(ctx); err != nil {
			return err
		}
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(b.info, info) ||
			runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
			return ErrNodeTransitUnavailable
		}
		return observer.identity(ctx)
	}
	if err := check(); err != nil {
		return err
	}
	switch mode {
	case networkPolicyTransitPrepared:
		// This validates owner identity, not a kernel adoption/add grant. The
		// shared backend separately requires exact absence before its first add.
		return check()
	case networkPolicyTransitRemoved:
		for _, name := range []string{policyAdditionFile, policyAdditionLock} {
			info, err := os.Lstat(filepath.Join(root, name))
			if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return ErrNodeTransitUnavailable
			}
		}
		status, err := nodeTransitReadEffects(ctx, observer.plan, root, observer.options.boot)
		if err != nil || !status.Removed || status.Unknown {
			return errors.Join(ErrNodeTransitUnavailable, err)
		}
	case networkPolicyTransitUnused:
		if b.unused == nil || b.unused.lease != b.lease {
			return ErrNodeTransitUnavailable
		}
		info, err := b.lease.unusedRoot(ctx)
		if err != nil || !os.SameFile(info, b.info) {
			return ErrNodeTransitUnavailable
		}
	default:
		return ErrNodeTransitUnavailable
	}
	count, err := observer.presence(ctx)
	if err != nil || count != 0 {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	if err := check(); err != nil {
		return err
	}
	if mode == networkPolicyTransitUnused {
		info, err := b.lease.unusedRoot(ctx)
		if err != nil || !os.SameFile(info, b.info) {
			return ErrNodeTransitUnavailable
		}
		// Only Manager's matched prepared record calls this mode, once. A failed
		// metadata save retains the resource and cannot replay the live proof.
		return b.unused.consumeUnused(ctx, spec, root, digest)
	}
	return ctx.Err()
}
