package app

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

// This owner reuses the structural Home observer and Store/control lifetime.
// Its only execution purpose is one selected IPv4 TCP/443 service. There is
// no conversion from a detached packet snapshot to a live owner.
type xrayHomeScopeBinding struct {
	self *xrayHomeScopeBinding
	base *NFQWSPacketScopeBinding
	// Immutable compilation inputs kept under base.mu until the one-time bind.
	planning   config.Config
	comparison DefaultRouteSnapshot
	service    dataplane.Route
	prepared   bool
}

func newReviewedStockXrayHomeScopeBinding(ctx context.Context, a *App, provider *netidentity.Provider) (*xrayHomeScopeBinding, error) {
	base, err := NewReviewedStockNC1812NFQWSPacketScopeBinding(ctx, a, provider)
	if err != nil {
		return nil, err
	}
	base.homePolicyProvider = provider
	h := &xrayHomeScopeBinding{base: base}
	h.self = h
	base.homeOwner = h
	if err = h.use(ctx, func(c context.Context) error { return c.Err() }); err != nil {
		return nil, errors.Join(err, h.Close())
	}
	return h, nil
}
func (h *xrayHomeScopeBinding) owned() bool {
	return h != nil && h.self == h && h.base != nil && h.base.self == h.base && h.base.homeOwner == h
}

func (h *xrayHomeScopeBinding) original() bool {
	return h.owned() && h.base.original != nil && h.base.physical == h.base.original &&
		h.base.homePolicyProvider != nil && h.base.app != nil && h.base.app.Store == h.base.store
}

func (h *xrayHomeScopeBinding) use(ctx context.Context, fn func(context.Context) error) error {
	if !h.original() {
		return ErrListScopeChanged
	}
	return h.base.use(ctx, fn)
}
func (h *xrayHomeScopeBinding) Close() error {
	if h == nil {
		return nil
	}
	if !h.owned() {
		return ErrListScopeChanged
	}
	return h.base.Close()
}
func (h *xrayHomeScopeBinding) observe(ctx context.Context) (DefaultRouteSnapshot, error) {
	var snap DefaultRouteSnapshot
	err := h.use(ctx, func(context.Context) error {
		s := h.base.snapshot
		snap = DefaultRouteSnapshot{Scope: autonomy.ScopeObservation{BootID: s.Facts.Identity.BootID, NetworkID: s.NetworkID, Revision: s.Facts.Intent.Revision}, Authority: s.Authority, DNSMode: s.DNSMode}
		return nil
	})
	return snap, err
}
func (h *xrayHomeScopeBinding) compile(ctx context.Context, cfg config.Config, snapshot DefaultRouteSnapshot, route dataplane.Route) (*DefaultRouteCompilation, error) {
	var out *DefaultRouteCompilation
	err := h.use(ctx, func(context.Context) error {
		if h.prepared || h.base.boundOnce || cfg.Revision != h.base.expected.Revision || !reflect.DeepEqual(cfg.NetworkPolicy, h.base.expected.NetworkPolicy) || !reflect.DeepEqual(cfg.DefaultRouteConsent, h.base.expected.DefaultRouteConsent) {
			return ErrListScopeChanged
		}
		var err error
		out, err = compileXrayHomeTCP(cfg, h.base.snapshot, snapshot, route)
		if err != nil {
			return err
		}
		h.planning = defaultRouteCloneConfig(cfg)
		h.comparison = defaultRouteClone(snapshot)
		h.service = defaultRouteCloneRoutes([]dataplane.Route{route})[0]
		h.prepared = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (h *xrayHomeScopeBinding) bind(ctx context.Context, c *DefaultRouteCompilation) error {
	return h.use(ctx, func(context.Context) error {
		if !h.prepared || h.base.boundOnce || c == nil {
			return ErrListScopeChanged
		}
		rebuilt, err := compileXrayHomeTCP(h.planning, h.base.snapshot, h.comparison, h.service)
		if err != nil || !reflect.DeepEqual(rebuilt, c) {
			return errors.Join(ErrListScopeChanged, err)
		}
		h.base.bound = c.LAN()
		h.base.boundOnce = true
		return nil
	})
}
func (h *xrayHomeScopeBinding) scopeCheck(c context.Context, plan *dataplane.LANPolicyRuntimePlan) error {
	if !h.original() {
		return ErrListScopeChanged
	}
	return h.base.ScopeCheck(c, plan)
}

func compileXrayHomeTCP(cfg config.Config, structural NFQWSPacketScopeSnapshot, snapshot DefaultRouteSnapshot, route dataplane.Route) (*DefaultRouteCompilation, error) {
	if err := validateNFQWSPacketSnapshot(cfg, structural); err != nil {
		return nil, err
	}
	facts := structural.Facts
	if cfg.Revision == 0 || cfg.Revision == ^uint64(0) ||
		snapshot.Scope.BootID != facts.Identity.BootID || snapshot.Scope.NetworkID != structural.NetworkID ||
		snapshot.Scope.Revision != facts.Intent.Revision || snapshot.Authority != structural.Authority ||
		snapshot.DNSMode != "baseline" || snapshot.NodeGeneration == 0 || snapshot.ProfileGeneration != snapshot.NodeGeneration || len(snapshot.Paths) != 1 {
		return nil, ErrListScopeChanged
	}
	id := route.ServiceID
	path := snapshot.Paths[id]
	state := cfg.Services[id]
	if id == "" || id == "default" || !state.Enabled ||
		!strings.HasPrefix(route.Selected, "xray:node-") || route.Selected != route.Resolved || state.Route != route.Selected ||
		path.Selected != route.Selected || path.Resolved != route.Resolved || path.ProbeURL != route.ProbeURL ||
		!defaultRoutePathValid(path) || path.NFQWS != nil || len(route.Domains) != 0 ||
		len(route.Sources) != 0 || len(route.SourceRefs) != 0 || len(route.CIDRs) != 1 {
		return nil, ErrDefaultRouteCapability
	}
	frozen := route.ProbeService
	if frozen == nil || frozen.ID != id || len(frozen.Domains) > 0 || len(frozen.SourceRefs) > 0 || !slices.Equal(frozen.CIDRs, route.CIDRs) || frozen.ProbeURL != route.ProbeURL {
		return nil, ErrDefaultRouteCapability
	}
	for other, st := range cfg.Services {
		if st.Enabled && other != id {
			return nil, ErrDefaultRouteCapability
		}
	}
	p := config.CloneNetworkPolicy(cfg.NetworkPolicy)
	if p.Traffic.Mode != "selected_services" || p.Traffic.AllExceptAllowed || p.Traffic.AutoHostlistAllowed {
		return nil, ErrDefaultRouteCapability
	}
	set, err := config.EffectiveResourceExclusions(p)
	if err != nil || len(set.BroadTLDs) > 0 {
		return nil, ErrDefaultRouteCapability
	}
	for _, list := range [][]config.ResourceMatch{set.Manual, set.Russian} {
		for _, m := range list {
			if m.Kind != "ip" && m.Kind != "cidr" {
				return nil, ErrDefaultRouteCapability
			}
		}
	}
	for _, rule := range p.Rules {
		if rule.Action != "direct" || (rule.Kind != "ip" && rule.Kind != "cidr") || len(rule.DeviceIDs) != 0 {
			return nil, ErrDefaultRouteCapability
		}
	}
	dest, err := defaultRouteParsePrefixes(route.CIDRs, true)
	if err != nil || len(dest) != 1 || !dest[0].Addr().Is4() || dest[0].Bits() != 32 {
		return nil, ErrDefaultRouteCapability
	}
	if !publicfetch.PublicPrefix(dest[0]) || !xrayHomeProbeMatches(route.ProbeURL, dest[0].Addr()) {
		return nil, ErrDefaultRouteCapability
	}
	for _, probe := range frozen.Probes {
		if probe.Required && !xrayHomeProbeMatches(probe.URL, dest[0].Addr()) {
			return nil, ErrDefaultRouteCapability
		}
	}
	public, err := defaultRoutePublic(p)
	if err != nil || !slices.Equal(defaultRouteIntersections(public, dest), dest) {
		return nil, ErrDefaultRouteCapability
	}
	gate, err := structuralHomeIngress(facts, p)
	if err != nil {
		return nil, err
	}
	// A /32 in the legacy dispatcher is a different single-client purpose.
	if len(gate.Sources) != 1 || gate.Sources[0].Bits() == 32 {
		return nil, ErrDefaultRouteCapability
	}
	// The provider/service proof pins the complete candidate. The packet owner
	// contributes only structural facts, never synthetic observed devices.
	c := &DefaultRouteCompilation{
		policy: p, snapshot: defaultRouteClone(snapshot), ingress: []DefaultRouteIngress{gate},
		rules: []DefaultRouteRule{{
			ServiceID: id, Origin: "override", Route: route.Resolved, Ingress: gate.Interface,
			Source: gate.Sources[0], Destination: dest[0], Protocol: "tcp", FirstPort: 443, LastPort: 443,
		}},
	}
	stable := structural
	stable.Facts = defaultRoutePacketFactsClone(facts)
	stable.Facts.ScopeID = ""
	c.digest = defaultRouteDigest(struct {
		Revision   uint64
		Policy     *config.NetworkPolicy
		Structural NFQWSPacketScopeSnapshot
		Snapshot   DefaultRouteSnapshot
		Service    dataplane.Route
		Ingress    DefaultRouteIngress
		Rules      []DefaultRouteRule
	}{cfg.Revision, p, stable, c.snapshot, route, gate, c.rules})
	lan, err := defaultRouteCompileLAN(c.digest, c.ingress)
	if err != nil {
		return nil, err
	}
	c.lan, err = dataplane.CompileXraySelectedTCPLANPolicyRuntime(c.digest, lan.Ingress)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// A service probe for a different host, protocol or port cannot establish
// health for this single literal /32 TCP/443 data path.
func xrayHomeProbeMatches(raw string, target netip.Addr) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.User == nil && u.Hostname() == target.String() && (u.Port() == "" || u.Port() == "443") && u.Fragment == ""
}

func (h *xrayHomeScopeBinding) transition(ctx context.Context, receipt *config.AutonomyRouteCommitReview, restored bool) error {
	if !h.original() || receipt == nil {
		return ErrListScopeChanged
	}
	b := h.base
	c, cancel, err := listScopeContext(ctx)
	if cancel != nil {
		defer cancel()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		return b.changed(err)
	}
	err = b.app.Operations.WithExclusiveContext(c, func() error {
		if b.closed || b.invalid || b.scope == nil || b.app.Store != b.store || !receipt.MatchesStore(b.store) {
			return b.changed(nil)
		}
		read := receipt.CommittedImages
		accept := b.scope.AcceptAutonomyCommitted
		if restored {
			read, accept = receipt.RestoredImages, b.scope.AcceptAutonomyRestored
		}
		before, after, err := read(c)
		if err != nil || !reflect.DeepEqual(before, b.expected) || !reflect.DeepEqual(before.NetworkPolicy, after.NetworkPolicy) || !reflect.DeepEqual(before.DefaultRouteConsent, after.DefaultRouteConsent) {
			return b.changed(err)
		}
		// The original scope owner consumes the sealed Store transition first.
		// Its physical selection is unchanged; structural verification below uses
		// the SAME Home owner instead of reopening after publication.
		if err := accept(c, receipt); err != nil {
			return b.changed(err)
		}
		closingBefore, closingAfter, err := read(c)
		if err != nil || !reflect.DeepEqual(before, closingBefore) || !reflect.DeepEqual(after, closingAfter) {
			return b.changed(err)
		}
		b.expected = closingAfter
		if err := b.currentLocked(c); err != nil {
			return err
		}
		// Physical/WAN callbacks have now joined. The actual receipt phase and
		// full Store image must still close this SAME publication or undo.
		finalBefore, finalAfter, err := read(c)
		if err != nil || !reflect.DeepEqual(before, finalBefore) || !reflect.DeepEqual(after, finalAfter) {
			return b.changed(err)
		}
		return nil
	})
	if err != nil {
		return b.changed(err)
	}
	return nil
}
