package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/ArtixSx/razvilka/internal/netresolve"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func (r *mihomoLiveResource) liveEndpointsCurrent(ctx context.Context) error {
	resolve := r.proxy.Resolver
	if resolve == nil {
		resolve = func(c context.Context, host string) ([]netip.Addr, error) {
			return netresolve.LookupNetIP(c, "ip", host)
		}
	}
	addresses, err := resolve(ctx, r.definition.EndpointHost)
	if err != nil {
		return errors.Join(errMihomoLiveMaterial, err)
	}
	addresses, err = mihomoLiveResolvedIPv4(addresses)
	if err != nil {
		return err
	}
	for _, address := range addresses {
		if err := r.resourceBoundary(ctx, r.definition.EndpointHost, address); err != nil {
			return err
		}
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Compare(addresses[j]) < 0 })
	addresses = slices.Compact(addresses)
	if !slices.Equal(addresses, r.definition.EndpointAddresses) {
		return ErrNodeEndpointChanged
	}
	return ctx.Err()
}

// This reader deliberately does not lock COMMON or call its guards: original
// NodeTransit readbacks invoke it while holding their own scope lock. Whole
// live health bookends it with currentBeforeStart/actual two-writer checks.
func (r *mihomoLiveResource) liveOwnersReadOnly(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if r == nil || r.self != r || r.proxy == nil || r.control == nil || r.source == nil || r.adapter == nil || r.scope == nil {
		return errMihomoLiveMaterial
	}
	if proxy, err := r.adapter.originalLiveProxy(r.scope.manager); err != nil || proxy != r.proxy {
		return errMihomoLiveMaterial
	}
	r.mu.Lock()
	child, sidecar, index := r.child, r.sidecar, r.tunIndex
	r.mu.Unlock()
	if child == nil || sidecar == nil || index < 1 {
		return errMihomoLiveMaterial
	}
	if cleanup == nil {
		if err := errors.Join(r.nativeCurrent(ctx), sidecar.current(ctx), r.liveEndpointsCurrent(ctx)); err != nil {
			return err
		}
	} else {
		if err := errors.Join(r.control.CurrentForCleanupOperation(ctx, cleanup), r.source.Current(ctx)); err != nil {
			return err
		}
		if err := r.nativeCleanupCurrent(ctx, cleanup); err != nil {
			return err
		}
	}
	actual, err := sidecar.tunInterfaceIndex(ctx, cleanup != nil)
	if err != nil || actual != index {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	return ctx.Err()
}

type mihomoLiveTUNCleanupKey struct{}

func (r *mihomoLiveResource) nodeTransitCleanupReview(ctx context.Context) (*operationgate.ExclusiveCleanupReview, error) {
	if actual, ok := ctx.Value(mihomoLiveTUNCleanupKey{}).(*operationgate.ExclusiveCleanupReview); ok {
		if err := r.control.CurrentForCleanupOperation(ctx, actual); err != nil {
			return nil, err
		}
		return actual, nil
	}
	r.mu.Lock()
	cleanup := r.cleanup
	r.mu.Unlock()
	if op, ok := ctx.Value(mihomoLiveOperationKey{}).(*mihomoLiveOperation); ok {
		if op == nil || op.self != op || op.owner != r || !op.open.Load() || op.forward {
			return nil, errMihomoLiveMaterial
		}
		cleanup = op.cleanup
	}
	if err := r.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return nil, err
	}
	return cleanup, nil
}

// currentLive earns service evidence from actual TUN-bound HTTPS sockets with
// original scoped transit rules and cleanup. A finite SOCKS result, Running()
// boolean or an adapter registration never enters this method as proof.
func (r *mihomoLiveResource) currentLive(ctx context.Context) error {
	return r.currentLiveObserved(ctx, false)
}

func (r *mihomoLiveResource) currentLiveObserved(ctx context.Context, handoff bool) error {
	if handoff {
		r.mu.Lock()
		r.healthHandoff = nil
		r.mu.Unlock()
	}
	ctx = r.resourceContext(ctx)
	if err := r.compiledCurrent(true); err != nil {
		return err
	}
	if r == nil || r.self != r || r.proxy == nil || r.scope == nil {
		return errMihomoLiveMaterial
	}
	if err := r.currentBeforeStart(ctx); err != nil {
		return err
	}
	// Do not consume more live rows while an already-full cohort cannot be
	// archived (for example, a retained controller still has reader7).
	if err := r.rotateMihomoTransit(ctx); err != nil {
		return err
	}
	if err := r.liveOwnersReadOnly(ctx, nil); err != nil {
		return err
	}
	cleanupReview, err := r.control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, mihomoLiveTUNCleanupKey{}, cleanupReview)
	a, plan, state := r.proxy, r.definition.Plan, r.definition.Policy
	if err := errors.Join(a.verifyForwarding(ctx, state), verifyPolicyEvidence(ctx, a.Runner, a.ip(), state)); err != nil {
		return err
	}
	root := filepath.Join(r.scope.root, "mihomo")
	if binding, exists, err := a.readPolicyBinding(state); err != nil {
		return err
	} else if exists {
		switch binding.Phase {
		case "active":
			root = ""
		case "removed":
		default:
			return ErrProxyPolicyUnknown
		}
	}
	generation, err := a.nodeRouterPolicyGeneration(ctx, state, root)
	if err != nil {
		return err
	}
	policy, err := a.captureNodeTransitPolicyAuthority(ctx, plan.PlanID, state, root, generation)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(a.TunnelCIDR)
	if err != nil || !prefix.Addr().Is4() {
		return errMihomoLiveMaterial
	}
	r.mu.Lock()
	index := r.tunIndex
	r.mu.Unlock()
	issuer, ok := ctx.Value(nodeTransitRegistrarKey{}).(nodeTransitRegistrar)
	if !ok || issuer == nil {
		return ErrNodeTransitUnavailable
	}
	verify := func(c context.Context, request nodeRouterHTTPSRequest, forward bool) error {
		var cleanup *operationgate.ExclusiveCleanupReview
		if !forward {
			var err error
			cleanup, err = r.nodeTransitCleanupReview(c)
			if err != nil {
				return err
			}
		}
		if err := r.liveOwnersReadOnly(c, cleanup); err != nil {
			return err
		}
		if err := policy.verify(c, a); err != nil {
			return err
		}
		if err := nodeRouterAssignedSource(c, request, nodeRouterHTTPSOptions{}); err != nil {
			return err
		}
		if forward {
			if err := nodeRouterReturnPath(c, a.Interface); err != nil {
				return err
			}
			return r.backendDisjoint(c, request.Source, request.Destination)
		}
		return c.Err()
	}
	observedDNS := make(map[string][]netip.Addr)
	for _, probe := range mihomoRequiredProbes(r.definition.Service) {
		service := cloneXraySelectedTCPService(r.definition.Service)
		service.ProbeURL = probe.URL
		predicate, err := newProxyServicePredicate(service)
		if err != nil {
			return err
		}
		addresses, err := resolveNodeServiceIPv4(ctx, probe.URL, a.Resolver)
		if err != nil || len(addresses) == 0 {
			return errors.Join(ErrNodeTransitUnavailable, err)
		}
		for _, destination := range addresses {
			if !nodeRouterPinInScope(destination, state.Prefixes) {
				return ErrNodeResourceDenied
			}
			if err := checkNodeResourceURL(ctx, probe.URL, destination); err != nil {
				return err
			}
			request := nodeRouterHTTPSRequest{URL: probe.URL, ServiceID: service.ID, Predicate: predicate, Interface: a.Interface, IfIndex: index, Source: prefix.Addr(), Destination: destination}
			if err := verify(ctx, request, true); err != nil {
				return err
			}
			spec := NodeTransitSpec{Schema: 1, Engine: "mihomo", BootID: r.definition.NetworkIdentity.BootID, PlanID: plan.PlanID, PlanDigest: plan.Digest, NetworkProfile: r.definition.NetworkProfile, RuntimeID: r.definition.Profile.ConfigSHA256, PolicyGeneration: generation, Interface: a.Interface, IfIndex: index, Source: request.Source, Destination: destination, Table: a.Table, Priority: 80}
			if err := validateNodeTransitSpec(spec); err != nil {
				return err
			}
			readback := &nodeRouterTransitReadback{spec: spec, owner: func(c context.Context) error { return verify(c, request, false) }}
			readback.self = readback
			operation := context.WithValue(ctx, networkPolicyTransitReadbackKey{}, networkPolicyTransitReadback(readback.readback))
			operation = context.WithValue(operation, nodeRouterTransitOriginalReadbackKey{}, readback)
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
		closing, err := resolveNodeServiceIPv4(ctx, probe.URL, a.Resolver)
		if err != nil || !slices.Equal(addresses, closing) {
			return errors.Join(ErrNodeEndpointChanged, err)
		}
		observedDNS[probe.URL] = slices.Clone(addresses)
	}
	if err := r.liveOwnersReadOnly(ctx, nil); err != nil {
		return err
	}
	if err := r.rotateMihomoTransit(ctx); err != nil {
		return err
	}
	if err := r.currentBeforeStart(ctx); err != nil {
		return err
	}
	if handoff {
		return r.issueHealthHandoff(ctx, policy, observedDNS)
	}
	return nil
}
