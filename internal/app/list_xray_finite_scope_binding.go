package app

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/defaultconsent"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

// xrayFiniteScopeBinding retains original config/control and one finite packet principal. It
// owns no executor, journal, effect admission or positive path/provider proof.
// Observe supplies only compiler data. CORE composes its actual path owners in
// DefaultRouteDependencies.Observe, then binds that compilation in BindIngress.
// ScopeCheck is the physical callback of the SAME LANPolicyRuntime participant.
// All uses require a fresh bounded context carrying the SAME App operation.
type xrayFiniteScopeBinding struct {
	self                       *xrayFiniteScopeBinding
	mu                         sync.Mutex
	app                        *App
	store                      *config.Store
	scope                      *defaultconsent.ScopeReview
	expected                   config.Config
	reference                  DefaultRouteAuthority
	facts                      physicalscope.FiniteIPv4PacketObservation
	networkID                  string
	network                    func(context.Context) (string, error)
	verifyPhysical             func(context.Context) error
	verifyCleanupPhysical      func(context.Context) error
	physicalObservation        func() physicalscope.FiniteIPv4PacketObservation
	closePhysical              func() error
	principal                  *physicalscope.FiniteIPv4PacketPrincipal
	compilation                *DefaultRouteCompilation
	boundRules                 []DefaultRouteRule
	bound                      *dataplane.LANPolicyRuntimePlan
	boundOnce, invalid, closed bool
	shapeInvalid               bool
	closeErr                   error
}

func (*xrayFiniteScopeBinding) String() string { return "[private original finite Xray scope binding]" }
func (*xrayFiniteScopeBinding) GoString() string {
	return "[private original finite Xray scope binding]"
}

// Production has one concrete source-owned finite issuer. This type never
// substitutes for ListScopeBinding and cannot expose a full physical Review.
func newReviewedStockXrayFiniteScopeBinding(ctx context.Context, a *App, provider *netidentity.Provider) (*xrayFiniteScopeBinding, error) {
	if provider == nil {
		return nil, ErrListScopeChanged
	}
	var principal *physicalscope.FiniteIPv4PacketPrincipal
	b, err := newXrayFiniteScopeBinding(ctx, a, func(c context.Context, selection physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.FiniteIPv4PacketObservation, func(context.Context) error, func() error, error) {
		var err error
		principal, err = physicalscope.NewReviewedStockNC1812FiniteIPv4PacketPrincipal(c, provider, selection)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return principal.Current, principal.Observation, principal.CurrentRetained, principal.Close, nil
	})
	if err != nil {
		return nil, err
	}
	b.principal = principal
	return b, nil
}

// acquire is a private source-level test seam. Production always constructs
// the concrete finite issuer above; tests explicitly model physics.
func newXrayFiniteScopeBinding(ctx context.Context, a *App, acquire func(context.Context, physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.FiniteIPv4PacketObservation, func(context.Context) error, func() error, error)) (*xrayFiniteScopeBinding, error) {
	c, cancel, err := listScopeContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if a == nil || a.Store == nil || acquire == nil {
		return nil, ErrListScopeChanged
	}
	b := &xrayFiniteScopeBinding{app: a, store: a.Store, network: a.FreshProfile}
	b.self = b
	if b.network == nil {
		b.network = func(c context.Context) (string, error) { p, err := systemprobe.FreshWANProfile(c); return p.ID, err }
	}
	keep := false
	defer func() {
		if !keep {
			_ = b.Close()
		}
	}()
	err = a.Operations.WithExclusiveContext(c, func() error {
		var err error
		b.scope, err = a.ReviewListScope(c)
		if err != nil {
			return err
		}
		b.expected = b.store.Get()
		b.reference, err = defaultRouteScopeAuthority(c, b.store, b.scope)
		if err != nil {
			return err
		}
		wanStarted := time.Now()
		b.networkID, err = b.network(c)
		recordManagedNFQTiming(c, managedNFQWANProfile, wanStarted)
		if err != nil || b.networkID == "" {
			return errors.Join(ErrListScopeChanged, err)
		}
		physicalStarted := time.Now()
		b.verifyPhysical, b.physicalObservation, b.verifyCleanupPhysical, b.closePhysical, err = acquire(c, b.selection)
		recordManagedNFQTiming(c, managedNFQPhysicalAcquire, physicalStarted)
		if err != nil || b.verifyPhysical == nil || b.physicalObservation == nil || b.closePhysical == nil || b.verifyCleanupPhysical == nil {
			return errors.Join(ErrListScopeChanged, err)
		}
		b.facts = b.physicalObservation()
		if b.facts.ReviewID == "" || b.facts.Identity.Validate() != nil || b.facts.Identity.Kind != netidentity.ReviewedSingleInitNet {
			return ErrListScopeChanged
		}
		if _, err := b.compilerScope(time.Now().UTC()); err != nil {
			return err
		}
		return b.currentLocked(c)
	})
	if err != nil {
		return nil, errors.Join(ErrListScopeChanged, err)
	}
	keep = true
	return b, nil
}

func (b *xrayFiniteScopeBinding) selection(ctx context.Context) (physicalscope.Selection, error) {
	if b.app.Store != b.store || !b.scope.MatchesConfigStore(b.store) {
		return physicalscope.Selection{}, ErrListScopeChanged
	}
	if err := b.scope.Current(ctx); err != nil {
		return physicalscope.Selection{}, err
	}
	cfg := b.store.Get()
	if !config.CurrentDefaultRouteScopeConsent(cfg) || cfg.NetworkPolicy == nil || cfg.DefaultRouteConsent == nil {
		return physicalscope.Selection{}, ErrListScopeChanged
	}
	s := physicalscope.Selection{Revision: cfg.DefaultRouteConsent.ApprovalRevision, PolicyRevision: cfg.NetworkPolicy.Revision, SegmentIDs: slices.Clone(cfg.NetworkPolicy.Clients.SegmentIDs)}
	if cfg.NetworkPolicy.Clients.Mode != "selected_devices" || cfg.NetworkPolicy.Clients.NewDevices != "base" || len(s.SegmentIDs) != 1 || len(cfg.NetworkPolicy.Clients.DeviceIDs) != 1 || cfg.NetworkPolicy.Traffic.Mode != "selected_services" {
		return physicalscope.Selection{}, ErrListScopeChanged
	}
	slices.Sort(s.SegmentIDs)
	if clients := cfg.NetworkPolicy.Clients; clients.Mode == "selected_devices" && clients.NewDevices == "base" {
		s.SelectedDevices = &physicalscope.SelectedDeviceProjection{DeviceIDs: slices.Clone(clients.DeviceIDs), ExcludedDeviceIDs: slices.Clone(clients.ExcludedDeviceIDs)}
		slices.Sort(s.SelectedDevices.DeviceIDs)
		slices.Sort(s.SelectedDevices.ExcludedDeviceIDs)
	}
	return s, b.scope.Current(ctx)
}

func (b *xrayFiniteScopeBinding) changed(err error) error {
	b.invalid = true
	return errors.Join(ErrListScopeChanged, err)
}

func (b *xrayFiniteScopeBinding) currentLocked(ctx context.Context) (resultErr error) {
	phase := "scope-owner"
	defer func() { resultErr = managedNFQFailureAt(phase, resultErr) }()
	if b.closed || b.invalid || b.scope == nil || b.verifyPhysical == nil || b.app.Store != b.store {
		return b.changed(nil)
	}
	if b.boundOnce && b.frozenCompilationCurrent() != nil {
		return b.changed(nil)
	}
	phase = "scope-authority-before"
	ref, err := defaultRouteScopeAuthority(ctx, b.store, b.scope)
	if err != nil || ref != b.reference || !reflect.DeepEqual(b.store.Get(), b.expected) {
		return b.changed(err)
	}
	phase = "scope-selection"
	selection, err := b.selection(ctx)
	if err != nil || !reflect.DeepEqual(selection, b.facts.Selection) {
		return b.changed(err)
	}
	phase = "scope-physical-verify"
	physicalStarted := time.Now()
	physicalErr := b.verifyPhysical(ctx)
	recordManagedNFQTiming(ctx, managedNFQPhysicalVerify, physicalStarted)
	if physicalErr != nil {
		return b.changed(physicalErr)
	}
	phase = "scope-physical-snapshot"
	if !reflect.DeepEqual(b.physicalObservation(), b.facts) {
		return b.changed(nil)
	}
	phase = "scope-wan-identity"
	wanStarted := time.Now()
	network, err := b.network(ctx)
	recordManagedNFQTiming(ctx, managedNFQWANProfile, wanStarted)
	if err != nil || network != b.networkID {
		return b.changed(err)
	}
	phase = "scope-authority-after"
	ref, err = defaultRouteScopeAuthority(ctx, b.store, b.scope)
	if err != nil || ref != b.reference || !reflect.DeepEqual(b.store.Get(), b.expected) {
		return b.changed(err)
	}
	return nil
}

func (b *xrayFiniteScopeBinding) use(ctx context.Context, action func(context.Context) error) error {
	if b == nil || b.self != b || b.app == nil {
		return ErrListScopeChanged
	}
	c, cancel, err := listScopeContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.app.Operations.WithExclusiveContext(c, func() error {
		if err := b.currentLocked(c); err != nil {
			return err
		}
		if err := action(c); err != nil {
			return err
		}
		return b.currentLocked(c)
	})
}

// Observe is the scope portion of DefaultRouteDependencies.Observe. The caller
// supplies fresh source/path proofs separately. Times describe this successful
// Verify only; the DTO never extends the live Review or authorizes an effect.
func (b *xrayFiniteScopeBinding) Observe(ctx context.Context) (DefaultRouteSnapshot, error) {
	var out DefaultRouteSnapshot
	err := b.use(ctx, func(context.Context) error {
		var err error
		out, err = b.compilerScope(time.Now().UTC())
		return err
	})
	if err != nil {
		return DefaultRouteSnapshot{}, err
	}
	return out, nil
}

func (b *xrayFiniteScopeBinding) compilerScope(now time.Time) (DefaultRouteSnapshot, error) {
	s := DefaultRouteSnapshot{Authority: b.reference, DNSMode: "baseline", Scope: autonomy.ScopeObservation{BootID: b.facts.Identity.BootID, NetworkID: b.networkID, Revision: b.facts.Selection.Revision, ObservedAt: now, FreshUntil: now.Add(time.Minute)}}
	aliases := map[string]string{}
	for _, segment := range b.facts.Segments {
		id := ""
		for _, selected := range b.facts.Selection.SegmentIDs {
			if selected == segment.ID || selected == segment.NativeName {
				if id != "" {
					return DefaultRouteSnapshot{}, ErrListScopeChanged
				}
				id = selected
			}
		}
		if id == "" || aliases[segment.ID] != "" || segment.Home == segment.Guest {
			return DefaultRouteSnapshot{}, ErrListScopeChanged
		}
		aliases[segment.ID] = id
		observed := autonomy.HomeSegment{ID: id, Interface: segment.Interface, Home: segment.Home}
		for _, raw := range segment.Prefixes {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix != prefix.Masked() {
				return DefaultRouteSnapshot{}, ErrListScopeChanged
			}
			observed.Prefixes = append(observed.Prefixes, prefix)
		}
		s.Scope.Segments = append(s.Scope.Segments, observed)
		for _, router := range segment.RouterNeighbors {
			s.Infrastructure = append(s.Infrastructure, DefaultRouteInfrastructureNeighbor{SegmentID: id, Interface: segment.Interface, Address: router.Address, MAC: router.MAC, Flags: router.Flags, Type: router.Type})
		}
		if segment.Guest {
			s.GuestSegmentIDs = append(s.GuestSegmentIDs, id)
		}
	}
	if len(aliases) != len(b.facts.Selection.SegmentIDs) {
		return DefaultRouteSnapshot{}, ErrListScopeChanged
	}
	for _, device := range b.facts.Devices {
		id := aliases[device.SegmentID]
		if id == "" {
			return DefaultRouteSnapshot{}, ErrListScopeChanged
		}
		s.Scope.Devices = append(s.Scope.Devices, autonomy.DeviceBinding{ID: device.ID, MAC: device.MAC, Interface: device.Interface, SegmentID: id, Confirmed: true})
		addresses := DefaultRouteDevice{ID: device.ID}
		for _, raw := range device.Addresses {
			ip, err := netip.ParseAddr(raw)
			if err != nil || !ip.IsGlobalUnicast() || ip.Is4In6() || ip.Zone() != "" {
				return DefaultRouteSnapshot{}, ErrListScopeChanged
			}
			addresses.Addresses = append(addresses.Addresses, ip)
		}
		s.Devices = append(s.Devices, addresses)
	}
	return s, nil
}

// BindCompilation runs in existing BindIngress after actual path compilation.
// It freezes one exact immutable LAN plan, without changing that plan or Input.
// It cannot grant the path/effect and cannot be rebound to another generation.
func (b *xrayFiniteScopeBinding) BindCompilation(ctx context.Context, compilation *DefaultRouteCompilation) error {
	return b.use(ctx, func(context.Context) (resultErr error) {
		phase := "bind-policy"
		defer func() { resultErr = managedNFQFailureAt(phase, resultErr) }()
		if compilation == nil || b.boundOnce || !reflect.DeepEqual(compilation.policy, b.expected.NetworkPolicy) {
			return ErrListScopeChanged
		}
		phase = "bind-observed-scope"
		actual, err := b.compilerScope(time.Now().UTC())
		if err != nil {
			return err
		}
		phase = "bind-snapshot"
		want, have := defaultRouteIdentity(actual), defaultRouteIdentity(compilation.snapshot)
		if have.Authority != want.Authority || have.DNSMode != "baseline" || have.Stopped || !reflect.DeepEqual(have.Scope, want.Scope) || !reflect.DeepEqual(have.Devices, want.Devices) || !slices.Equal(have.Infrastructure, want.Infrastructure) || !slices.Equal(have.GuestSegmentIDs, want.GuestSegmentIDs) {
			return ErrListScopeChanged
		}
		plan := compilation.LAN()
		if plan != nil {
			phase = "bind-lan-plan"
			if err := dataplane.ValidateLANPolicyRuntime(plan); err != nil {
				return errors.Join(ErrListScopeChanged, err)
			}
			phase = "bind-lan-generation"
			if plan.Generation != compilation.Digest() {
				return ErrListScopeChanged
			}
			phase = "bind-router-membership"
			for _, segment := range b.facts.Segments {
				for _, router := range segment.RouterNeighbors {
					// The frozen LAN plan uses canonical uppercase MACs while
					// native physical facts use net.HardwareAddr's lowercase form.
					routerMAC := strings.ToUpper(router.MAC)
					for _, ingress := range plan.Ingress {
						if ingress.Interface == segment.Interface && !slices.Contains(ingress.ExcludedMACs, routerMAC) {
							return ErrListScopeChanged
						}
					}
				}
			}
		}
		if err := b.finiteCompilation(compilation); err != nil {
			return err
		}
		b.compilation, b.boundRules = compilation, slices.Clone(compilation.rules)
		b.bound, b.boundOnce = dataplane.CloneLANPolicyRuntime(plan), true
		return nil
	})
}

func (b *xrayFiniteScopeBinding) ScopeCheck(ctx context.Context, plan *dataplane.LANPolicyRuntimePlan) error {
	if b == nil || b.self != b || b.app == nil {
		return ErrListScopeChanged
	}
	c, cancel, err := listScopeContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.app.Operations.WithExclusiveContext(c, func() error {
		// This comparison touches no external state or effects. Close it with
		// one complete fresh owner read under SAME mutex and actual operation,
		// including when the proposed immutable plan itself mismatches.
		var comparison error
		if !b.boundOnce || b.bound == nil || dataplane.ValidateLANPolicyRuntime(plan) != nil || !reflect.DeepEqual(plan, b.bound) || b.frozenCompilationCurrent() != nil {
			comparison = ErrListScopeChanged
		}
		return errors.Join(comparison, b.currentLocked(c))
	})
}

// Call only after SAME Store's exact successful policy CAS, outside Store
// observation, with actual commit times. The original ScopeReview accepts the
// sanctioned image first; failed physical verification then poisons this owner.
// No ordinary edit, restored tuple or copied postimage can renew the binding.
func (b *xrayFiniteScopeBinding) AcceptCommitted(ctx context.Context, after config.Config, started, finished time.Time) error {
	if b == nil || b.self != b || b.app == nil {
		return ErrListScopeChanged
	}
	c, cancel, err := listScopeContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.app.Operations.WithExclusiveContext(c, func() error {
		if b.closed || b.invalid || b.scope == nil || b.app.Store != b.store {
			return b.changed(nil)
		}
		actual := b.store.Get()
		if !reflect.DeepEqual(actual, after) || !defaultRouteCommittedConfig(b.expected, actual, b.expected.NetworkPolicy, b.expected.Services, started, finished) {
			return b.changed(nil)
		}
		if err := b.scope.AcceptCommitted(c, actual, started, finished); err != nil {
			return b.changed(err)
		}
		b.expected = actual // Store.Get's detached clone, never the caller DTO
		return b.currentLocked(c)
	})
}

func (b *xrayFiniteScopeBinding) Close() error {
	if b == nil {
		return nil
	}
	if b.self != b {
		return ErrListScopeChanged
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return b.closeErr
	}
	b.closed = true
	if b.closePhysical != nil {
		b.closeErr = b.closePhysical()
	}
	if b.scope != nil {
		b.closeErr = errors.Join(b.closeErr, b.scope.Close())
	}
	return b.closeErr
}

// cleanupScopeCheck compares only the SAME original retained physics and
// immutable bound LAN plan. The concrete App cleanup owner calls this inside
// its actual pre-issued operation cleanup capability. This read grants no
// command, process ownership or forward scope and never reads Store/selection.
func (b *xrayFiniteScopeBinding) cleanupScopeCheck(ctx context.Context, plan *dataplane.LANPolicyRuntimePlan) error {
	if b == nil || b.self != b || b.app == nil || ctx == nil {
		return ErrListScopeChanged
	}
	c, cancel, err := listScopeContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.app.Store != b.store || !b.boundOnce || b.bound == nil || b.verifyCleanupPhysical == nil || b.physicalObservation == nil || dataplane.ValidateLANPolicyRuntime(plan) != nil || !reflect.DeepEqual(b.bound, plan) || b.frozenCompilationCurrent() != nil || !reflect.DeepEqual(b.facts, b.physicalObservation()) {
		return ErrListScopeChanged
	}
	if err := b.verifyCleanupPhysical(c); err != nil {
		return errors.Join(ErrListScopeChanged, err)
	}
	if b.closed || !reflect.DeepEqual(b.facts, b.physicalObservation()) {
		return ErrListScopeChanged
	}
	return c.Err()
}

// These transitions consume only the actual SAME Store's single-service
// writer/undo receipt. They retain the original ScopeReview and physical
// Review, and supply no node proof, effect admission or cleanup permission.
func (b *xrayFiniteScopeBinding) AcceptAutonomyCommitted(ctx context.Context, receipt *config.AutonomyRouteCommitReview) error {
	return b.acceptAutonomyTransition(ctx, receipt, false)
}

func (b *xrayFiniteScopeBinding) AcceptAutonomyRestored(ctx context.Context, receipt *config.AutonomyRouteCommitReview) error {
	return b.acceptAutonomyTransition(ctx, receipt, true)
}

func (b *xrayFiniteScopeBinding) acceptAutonomyTransition(ctx context.Context, receipt *config.AutonomyRouteCommitReview, restored bool) error {
	if b == nil || b.self != b || b.app == nil {
		return ErrListScopeChanged
	}
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
		// Its physical selection is unchanged; finite verification below uses
		// the SAME finite issuer instead of reopening after publication.
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

// The original App issuer, not the general Xray mode/compiler, freezes this
// purpose. A future broader consumer cannot acquire these finite physics.
func (b *xrayFiniteScopeBinding) finiteCompilation(c *DefaultRouteCompilation) error {
	if b == nil || c == nil || c.lan == nil || c.lan.Mode != dataplane.LANPolicyXraySelectedTCPMode || dataplane.ValidateLANPolicyRuntime(c.lan) != nil || c.lan.Generation != c.Digest() || c.snapshot.DNSMode != "baseline" || len(c.rules) == 0 || len(c.lan.Ingress) != 1 || b.facts.Selection.SelectedDevices == nil || len(b.facts.Selection.SelectedDevices.DeviceIDs) != 1 {
		return ErrListScopeChanged
	}
	g := c.lan.Ingress[0]
	if g.Membership != "mac" || len(g.IncludedMACs) != 1 || len(g.Sources) != 1 || len(g.ExcludedSources) != 0 || len(b.facts.Segments) != 1 || g.Interface != b.facts.Segments[0].Interface {
		return ErrListScopeChanged
	}
	source, err := netip.ParsePrefix(g.Sources[0])
	if err != nil || !source.Addr().Is4() || source.Bits() != 32 {
		return ErrListScopeChanged
	}
	found := 0
	for _, d := range b.facts.Devices {
		if d.ID != b.facts.Selection.SelectedDevices.DeviceIDs[0] {
			continue
		}
		if d.Interface != g.Interface || d.IfIndex != b.facts.Segments[0].IfIndex || !strings.EqualFold(d.MAC, g.IncludedMACs[0]) {
			return ErrListScopeChanged
		}
		count := 0
		for _, raw := range d.Addresses {
			ip, err := netip.ParseAddr(raw)
			if err != nil {
				return ErrListScopeChanged
			}
			if ip.Is4() {
				count++
				if ip != source.Addr() {
					return ErrListScopeChanged
				}
			}
		}
		if count != 1 {
			return ErrListScopeChanged
		}
		found++
	}
	if found != 1 {
		return ErrListScopeChanged
	}
	service, route := c.rules[0].ServiceID, c.rules[0].Route
	if service == "" || !strings.HasPrefix(route, "xray:node-") {
		return ErrListScopeChanged
	}
	for _, rule := range c.rules {
		if rule.ServiceID != service || rule.Route != route || rule.Ingress != g.Interface || rule.Source != source || rule.Protocol != "tcp" || rule.FirstPort != 443 || rule.LastPort != 443 || !rule.Destination.Addr().Is4() || rule.Destination != rule.Destination.Masked() || !publicfetch.PublicPrefix(rule.Destination) {
			return ErrListScopeChanged
		}
	}
	for _, d := range b.facts.Devices {
		if slices.Contains(b.facts.Selection.SelectedDevices.ExcludedDeviceIDs, d.ID) && !slices.Contains(g.ExcludedMACs, strings.ToUpper(d.MAC)) {
			return ErrListScopeChanged
		}
	}
	for _, segment := range b.facts.Segments {
		for _, router := range segment.RouterNeighbors {
			if !slices.Contains(g.ExcludedMACs, strings.ToUpper(router.MAC)) {
				return ErrListScopeChanged
			}
		}
	}
	return nil
}

// Actual original compilation drift is sticky; a wrong proposed plan alone
// cannot revoke the separately retained original cleanup shape.
func (b *xrayFiniteScopeBinding) frozenCompilationCurrent() error {
	if b.shapeInvalid || b.bound == nil || b.finiteCompilation(b.compilation) != nil || !slices.Equal(b.boundRules, b.compilation.rules) || !reflect.DeepEqual(b.bound, b.compilation.lan) || b.bound.Generation != b.compilation.Digest() {
		b.shapeInvalid = true
		return ErrListScopeChanged
	}
	return nil
}
