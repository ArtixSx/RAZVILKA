package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// This memory-only comparison belongs to one original Health/Commit pair.
// It cannot establish fresh service health, survive a request or authorize an
// effect. Commit still performs mandatory HTTPS again AFTER policy promotion.
type mihomoLiveHealthHandoff struct {
	self         *mihomoLiveHealthHandoff
	owner        *mihomoLiveResource
	scope        *executionResourceScope
	child        *components.MihomoLiveProcess
	sidecar      *mihomoLiveSidecar
	control      *operationgate.ControlEpochReview
	scopeContext context.Context
	context      context.Context
	deadline     time.Time
	policy       *nodeTransitPolicyAuthority
	dns          map[string][]netip.Addr
}

func (r *mihomoLiveResource) issueHealthHandoff(ctx context.Context, policy *nodeTransitPolicyAuthority, dns map[string][]netip.Addr) error {
	deadline, finite := ctx.Deadline()
	if !finite || !time.Now().Before(deadline) || ctx.Err() != nil || r.scope == nil || r.scope.ctx == nil || r.scope.ctx.Err() != nil || ctx.Value(syntheticExecutionRegistrarKey{}) != r.scope || policy == nil || !policy.candidate || len(dns) == 0 {
		return errors.Join(errMihomoLiveMaterial, ctx.Err())
	}
	if err := policy.verify(ctx, r.proxy); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.self != r || r.closed || r.active || r.retired || r.child == nil || r.sidecar == nil || r.healthHandoff != nil {
		return errMihomoLiveMaterial
	}
	h := &mihomoLiveHealthHandoff{owner: r, scope: r.scope, child: r.child, sidecar: r.sidecar, control: r.control, scopeContext: r.scope.ctx, context: ctx, deadline: deadline, policy: policy, dns: make(map[string][]netip.Addr, len(dns))}
	h.self = h
	for url, addresses := range dns {
		h.dns[url] = slices.Clone(addresses)
	}
	r.healthHandoff = h
	return nil
}

// Taking the marker consumes it even on refusal. Native and kernel checks
// below remain necessary: possessing this private marker is never sufficient.
func (r *mihomoLiveResource) takeHealthHandoff(ctx context.Context) (*mihomoLiveHealthHandoff, error) {
	if r == nil || ctx == nil {
		return nil, errMihomoLiveMaterial
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.healthHandoff
	r.healthHandoff = nil
	deadline, finite := ctx.Deadline()
	if !h.ownerCurrentLocked(r) || ctx.Value(syntheticExecutionRegistrarKey{}) != r.scope || h.context.Err() != nil || h.scopeContext.Err() != nil || !finite || !time.Now().Before(deadline) || !time.Now().Before(h.deadline) || ctx.Err() != nil {
		var prior error
		if h != nil && h.context != nil {
			prior = h.context.Err()
		}
		if h != nil && h.scopeContext != nil {
			prior = errors.Join(prior, h.scopeContext.Err())
		}
		return nil, errors.Join(errMihomoLiveMaterial, prior, ctx.Err())
	}
	return h, nil
}

func (h *mihomoLiveHealthHandoff) ownerCurrentLocked(r *mihomoLiveResource) bool {
	return h != nil && h.self == h && r != nil && r.self == r && !r.closed && !r.active && !r.retired && h.owner == r && r.scope != nil && h.scope == r.scope && h.child == r.child && h.sidecar == r.sidecar && h.control == r.control && h.context != nil && h.scopeContext != nil && h.scopeContext == r.scope.ctx
}

// Commit has an existing finite kernel-mutation shield with a different
// deadline. The comparison cannot inherit that longer lifetime: cap it to
// the ORIGINAL Health deadline and join cancellation of both original owners.
func (h *mihomoLiveHealthHandoff) comparisonContext(ctx context.Context) (context.Context, func()) {
	held, cancel := context.WithDeadline(ctx, h.deadline)
	stopRequest := context.AfterFunc(h.context, cancel)
	stopScope := context.AfterFunc(h.scopeContext, cancel)
	return held, func() { stopRequest(); stopScope(); cancel() }
}

// Network guard callbacks between Health and Commit cannot refresh the marker.
// Re-observe every structural owner, the ORIGINAL candidate policy authority,
// and every current service DNS answer before making the promotion effect.
func (r *mihomoLiveResource) verifyHealthHandoff(ctx context.Context) error {
	h, err := r.takeHealthHandoff(ctx)
	if err != nil {
		return err
	}
	if h.policy == nil || !h.policy.candidate || len(h.dns) == 0 {
		return errMihomoLiveMaterial
	}
	ctx, finish := h.comparisonContext(ctx)
	defer finish()
	if err := r.compiledCurrent(true); err != nil {
		return err
	}
	if err := r.currentBeforeStart(ctx); err != nil {
		return err
	}
	if err := r.liveOwnersReadOnly(ctx, nil); err != nil {
		return err
	}
	a, state := r.proxy, r.definition.Policy
	if proxyPolicyDigest(state) != h.policy.digest {
		return ErrProxyPolicyUnknown
	}
	if err := errors.Join(h.policy.verify(ctx, a), a.verifyForwarding(ctx, state), verifyPolicyEvidence(ctx, a.Runner, a.ip(), state)); err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(a.TunnelCIDR)
	if err != nil || !prefix.Addr().Is4() {
		return errMihomoLiveMaterial
	}
	r.mu.Lock()
	index := r.tunIndex
	r.mu.Unlock()
	probes := mihomoRequiredProbes(r.definition.Service)
	seen := make(map[string]bool, len(probes))
	for _, probe := range probes {
		addresses, err := resolveNodeServiceIPv4(ctx, probe.URL, a.Resolver)
		if err != nil || !mihomoHealthDNSMatches(h.dns, probe.URL, addresses) {
			return errors.Join(ErrNodeEndpointChanged, err)
		}
		seen[probe.URL] = true
		for _, destination := range addresses {
			if !nodeRouterPinInScope(destination, state.Prefixes) {
				return ErrNodeResourceDenied
			}
			if err := checkNodeResourceURL(ctx, probe.URL, destination); err != nil {
				return err
			}
			request := nodeRouterHTTPSRequest{Interface: a.Interface, IfIndex: index, Source: prefix.Addr(), Destination: destination}
			if err := nodeRouterAssignedSource(ctx, request, nodeRouterHTTPSOptions{}); err != nil {
				return err
			}
			if err := nodeRouterReturnPath(ctx, a.Interface); err != nil {
				return err
			}
			if err := r.backendDisjoint(ctx, request.Source, request.Destination); err != nil {
				return err
			}
		}
		closing, err := resolveNodeServiceIPv4(ctx, probe.URL, a.Resolver)
		if err != nil || !mihomoHealthDNSMatches(h.dns, probe.URL, closing) {
			return errors.Join(ErrNodeEndpointChanged, err)
		}
	}
	if len(seen) != len(h.dns) {
		return ErrNodeEndpointChanged
	}
	if err := errors.Join(h.policy.verify(ctx, a), a.verifyForwarding(ctx, state), verifyPolicyEvidence(ctx, a.Runner, a.ip(), state), r.liveOwnersReadOnly(ctx, nil)); err != nil {
		return err
	}
	if err := r.currentBeforeStart(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	current := h.ownerCurrentLocked(r)
	r.mu.Unlock()
	if !current {
		return errMihomoLiveMaterial
	}
	if err := errors.Join(ctx.Err(), h.context.Err(), h.scopeContext.Err()); err != nil {
		return err
	}
	if !time.Now().Before(h.deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func mihomoHealthDNSMatches(observed map[string][]netip.Addr, url string, current []netip.Addr) bool {
	before, exists := observed[url]
	return exists && len(before) > 0 && slices.Equal(before, current)
}
