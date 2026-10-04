package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

const nodeRouterHealthBudget = 30 * time.Second

type nodeRouterAdmittedProbe struct {
	request nodeRouterHTTPSRequest
}

func nodeRouterPinInScope(destination netip.Addr, prefixes []string) bool {
	for _, raw := range prefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && prefix.Contains(destination) {
			return true
		}
	}
	return false
}

func (a *ProxyTunnelAdapter) nodeRouterPolicyGeneration(ctx context.Context, state PolicyState, root string) (string, error) {
	if root != "" {
		receipt, err := a.readCandidatePolicyReceipt(root, state)
		if err != nil || receipt.Phase != "complete" {
			return "", ErrNodeTransitUnavailable
		}
		status, err := nodeTransitReadAddition(ctx, state, root, a.currentBootIdentity)
		if err != nil || !status.Complete || status.Unknown {
			return "", ErrNodeTransitUnavailable
		}
		return status.ID, nil
	}
	binding, exists, err := a.readPolicyBinding(state)
	if err != nil || !exists || binding.Phase != "active" {
		return "", ErrNodeTransitUnavailable
	}
	committed, err := a.policyGenerationRoot(binding.Generation)
	if err != nil {
		return "", err
	}
	status, err := nodeTransitReadAddition(ctx, state, committed, a.currentBootIdentity)
	if err != nil || !status.Complete || status.Unknown || status.ID != binding.ReceiptID {
		return "", errors.Join(ErrNodeTransitUnavailable, err)
	}
	return binding.Generation, nil
}

// Resolve all admitted pins before issuing any temporary resource. Fresh DNS
// may narrow the configured scope, but cannot extend Xray's materialized IP
// allowlist or replace a reviewed full service predicate.
func (a *ProxyTunnelAdapter) nodeRouterAdmittedProbes(ctx context.Context, manifest proxyNodeManifest, source netip.Addr, index int) ([]nodeRouterAdmittedProbe, error) {
	if len(manifest.Routes) == 0 || len(manifest.Routes) != len(manifest.Requests) {
		return nil, ErrNodeTransitUnavailable
	}
	var result []nodeRouterAdmittedProbe
	for i, route := range manifest.Routes {
		service, err := FrozenProbeService(route)
		if err != nil {
			return nil, err
		}
		predicate, err := newProxyServicePredicate(service)
		if err != nil {
			return nil, err
		}
		addresses, err := resolveNodeServiceIPv4(ctx, route.ProbeURL, a.Resolver)
		if err != nil || len(addresses) == 0 || len(addresses) > 64-len(result) {
			return nil, ErrNodeTransitUnavailable
		}
		for _, destination := range addresses {
			if !nodeRouterPinInScope(destination, manifest.Requests[i].Destinations) {
				return nil, ErrNodeEndpointChanged
			}
			for _, endpoint := range manifest.Endpoints {
				if endpoint.IP == destination.String() {
					return nil, ErrNodeTransitUnavailable
				}
			}
			result = append(result, nodeRouterAdmittedProbe{request: nodeRouterHTTPSRequest{
				URL: route.ProbeURL, ServiceID: service.ID, Predicate: predicate, Interface: a.Interface, IfIndex: index, Source: source, Destination: destination,
			}})
		}
	}
	return result, ctx.Err()
}

func (a *ProxyTunnelAdapter) scopedNodeRouterHealth(ctx context.Context, plan Plan, state PolicyState, root string) error {
	if ctx == nil || a == nil || !a.nodeRouterVerifier || !a.NodeRouteVerificationCapable() {
		return ErrNodeTransitUnavailable
	}
	if err := requireOwnedUSQUEReviewGuard(ctx); err != nil {
		return err
	}
	issuer, ok := ctx.Value(nodeTransitRegistrarKey{}).(nodeTransitRegistrar)
	if !ok || issuer == nil {
		return ErrNodeTransitUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, nodeRouterHealthBudget)
	defer cancel()
	if err := a.verifyScopedNodeInterface(ctx); err != nil {
		return err
	}
	manifest, err := a.checkScopedNodeState(ctx, plan)
	if err != nil {
		return err
	}
	runtimeID, err := a.scopedRuntimeIdentity()
	if err != nil {
		return err
	}
	boot, err := a.currentBootIdentity()
	if err != nil {
		return err
	}
	generation, err := a.nodeRouterPolicyGeneration(ctx, state, root)
	if err != nil {
		return err
	}
	index, err := a.scopedInterfaceIndex(ctx)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(a.TunnelCIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.Addr().Is4In6() {
		return ErrNodeTransitUnavailable
	}
	// Prefix.Addr is the actual assigned address; Masked().Addr is not a source.
	source := prefix.Addr()
	probes, err := a.nodeRouterAdmittedProbes(ctx, manifest, source, index)
	if err != nil {
		return err
	}
	manifestRaw, _ := json.Marshal(manifest)
	manifestHash := routeidentity.Hash(manifestRaw)
	priority := 0
	for _, owner := range NodeTransitOwnershipSpecs() {
		if owner.Engine == a.ID() && owner.Interface == a.Interface && owner.Table == a.Table {
			priority = owner.Priority
		}
	}
	if priority == 0 {
		return ErrNodeTransitUnavailable
	}
	verify := func(c context.Context, request nodeRouterHTTPSRequest, active bool) error {
		if c.Err() != nil {
			return c.Err()
		}
		if active {
			if err := requireOwnedUSQUEReviewGuard(c); err != nil {
				return err
			}
			if err := a.checkPlanNetwork(c, plan); err != nil {
				return err
			}
		}
		currentBoot, err := a.currentBootIdentity()
		if err != nil || currentBoot != boot {
			return ErrNodeTransitUnavailable
		}
		if err := a.verifyScopedNodeInterface(c); err != nil {
			return err
		}
		currentRuntime, err := a.scopedRuntimeIdentity()
		if err != nil || currentRuntime != runtimeID {
			return ErrNodeTransitUnavailable
		}
		currentManifest, err := a.readNodeManifest(a.nodeManifestPath())
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(currentManifest)
		if routeidentity.Hash(raw) != manifestHash {
			return ErrNodeTransitUnavailable
		}
		currentState, exists, err := a.loadPolicy()
		if err != nil || !exists || proxyPolicyDigest(currentState) != proxyPolicyDigest(state) {
			return ErrNodeTransitUnavailable
		}
		currentGeneration, err := a.nodeRouterPolicyGeneration(c, state, root)
		if err != nil || currentGeneration != generation {
			return ErrNodeTransitUnavailable
		}
		if err := nodeRouterAssignedSource(c, request, nodeRouterHTTPSOptions{}); err != nil {
			return err
		}
		if active {
			if err := nodeRouterReturnPath(c, a.Interface); err != nil {
				return err
			}
			return a.nodeRouterBackendDisjoint(c, manifest, source, request.Destination)
		}
		return c.Err()
	}
	for _, probe := range probes {
		request := probe.request
		if err := verify(ctx, request, true); err != nil {
			return err
		}
		spec := NodeTransitSpec{Schema: 1, Engine: a.ID(), BootID: boot, PlanID: plan.PlanID, PlanDigest: plan.Digest,
			NetworkProfile: plan.NetworkProfileID, RuntimeID: runtimeID, PolicyGeneration: generation, Interface: a.Interface, IfIndex: index,
			Source: source, Destination: request.Destination, Table: a.Table, Priority: priority}
		if err := validateNodeTransitSpec(spec); err != nil {
			return err
		}
		readback := &nodeRouterTransitReadback{spec: spec, owner: func(c context.Context) error { return verify(c, request, false) }}
		operation := context.WithValue(ctx, networkPolicyTransitReadbackKey{}, networkPolicyTransitReadback(readback.readback))
		registration, err := issuer(operation, spec)
		if err != nil {
			return err
		}
		if registration.root == "" || registration.register == nil || registration.settle == nil || registration.cleanupGuard == nil {
			return ErrNodeTransitUnavailable
		}
		readback.root = registration.root
		readback.info, err = os.Lstat(registration.root)
		if err != nil {
			return err
		}
		if err := a.runRegisteredNodeRouterProbe(operation, spec, registration, request, verify, readback); err != nil {
			return err
		}
	}
	if err := a.verifyHealthRuntime(ctx, state); err != nil {
		return err
	}
	return a.checkPlanNetwork(ctx, plan)
}

type nodeTransitCleanupKey struct{}

func (a *ProxyTunnelAdapter) runRegisteredNodeRouterProbe(ctx context.Context, spec NodeTransitSpec, registration nodeTransitRegistration,
	request nodeRouterHTTPSRequest, verify func(context.Context, nodeRouterHTTPSRequest, bool) error, readback *nodeRouterTransitReadback) (resultErr error) {
	guard := func(c context.Context, _ NodeTransitSpec) error {
		cleanup, _ := c.Value(nodeTransitCleanupKey{}).(bool)
		if cleanup {
			if err := registration.cleanupGuard(c); err != nil {
				return err
			}
		}
		return verify(c, request, !cleanup)
	}
	lease, err := newNodeTransitLease(spec, registration.root, nodeTransitRuntime{runner: a.Runner, ip: a.ip(),
		preflight: guard, guard: guard, beforeDelete: guard, register: registration.register})
	if err != nil {
		return err
	}
	readback.lease = lease
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithValue(context.WithoutCancel(ctx), nodeTransitCleanupKey{}, true), 10*time.Second)
		defer cancel()
		if isNodeTransitBeforeEffects(resultErr) {
			// Only this live lease's one-shot proof permits metadata-only
			// settlement. A crash, absent file, unknown ACK or new lease cannot.
			if registration.settleUnused == nil {
				return
			}
			if err := registration.cleanupGuard(cleanup); err != nil {
				resultErr = errors.Join(resultErr, err)
				return
			}
			if err := lease.VerifyUnused(cleanup); err != nil {
				resultErr = errors.Join(resultErr, err)
				return
			}
			if !errors.As(resultErr, &readback.unused) || readback.unused == nil || readback.unused.lease != lease {
				resultErr = errors.Join(resultErr, ErrNodeTransitUnavailable)
				return
			}
			if err := registration.settleUnused(cleanup, spec, registration.root, lease.digest); err != nil {
				resultErr = errors.Join(resultErr, err)
			}
			return
		}
		if err := lease.Remove(cleanup); err != nil {
			resultErr = errors.Join(resultErr, err)
			return
		}
		status, err := lease.Inspect(cleanup)
		if err != nil || !status.Removed || status.Unknown {
			resultErr = errors.Join(resultErr, ErrNodeTransitUnavailable, err)
			return
		}
		count, err := lease.presence(cleanup)
		if err != nil || count != 0 {
			resultErr = errors.Join(resultErr, ErrNodeTransitUnavailable, err)
			return
		}
		if err := registration.settle(cleanup, spec, registration.root, lease.digest); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	if err := lease.Apply(ctx); err != nil {
		return err
	}
	if err := lease.VerifyRoute(ctx); err != nil {
		return err
	}
	if err := verify(ctx, request, true); err != nil {
		return err
	}
	result, err := probeNodeRouterHTTPS(ctx, request)
	if err != nil {
		return err
	}
	if !result.ServiceAccepted || result.Origin != nodeRouterHTTPSOrigin || result.ServiceID != request.ServiceID ||
		result.PredicateHash != request.Predicate.digest() || result.Source.Addr() != spec.Source || result.Destination.Addr() != spec.Destination ||
		result.Interface != spec.Interface || result.IfIndex != spec.IfIndex {
		return ErrNodeTransitUnavailable
	}
	if err := lease.VerifyRoute(ctx); err != nil {
		return err
	}
	return verify(ctx, request, true)
}
