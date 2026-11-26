package app

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"sync"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

// A finite round retains typed packet facts, never a successful full Snapshot.
// It shares the original round's Store/control/context owner with the full
// reader, but cannot be adopted by its full Observer/Review borrow path.
type autonomyXrayFiniteDeviceScope struct {
	self      *autonomyXrayFiniteDeviceScope
	owner     *autonomyDeviceScope
	purpose   *autonomyXrayFinitePurpose
	facts     physicalscope.FiniteIPv4PacketObservation
	principal *physicalscope.FiniteIPv4PacketPrincipal
	verify    func(context.Context) error
	observe   func() physicalscope.FiniteIPv4PacketObservation
	retained  func(context.Context) error
}

type autonomyXrayFinitePurpose struct {
	policy  autonomy.Policy
	spec    autonomy.Service
	service catalog.Service
	runtime *ManagedXraySelectedTCPListRuntime
}

// Choose only a single enrolled Xray node service and one selected attachment.
// Startup ownership is sufficient: no active execution or healthy old A is
// required for the first candidate or a round after completed retirement.
func (a *App) autonomyXrayFinitePurpose(cfg config.Config, startup *managedListPolicyOwner) *autonomyXrayFinitePurpose {
	if a == nil || !config.CurrentDefaultRouteScopeConsent(cfg) || cfg.NetworkPolicy == nil {
		return nil
	}
	clients := cfg.NetworkPolicy.Clients
	if clients.Mode != "selected_devices" || clients.NewDevices != "base" || len(clients.DeviceIDs) != 1 || len(clients.SegmentIDs) != 1 || cfg.NetworkPolicy.Traffic.Mode != "selected_services" {
		return nil
	}
	a.managedXraySelectedTCPListMu.Lock()
	r := a.managedXraySelectedTCPList
	ready := r.original() && startup != nil && r.policy == startup
	a.managedXraySelectedTCPListMu.Unlock()
	if !ready {
		return nil
	}
	a.autonomy.mu.Lock()
	p := autonomy.Clone(a.autonomy.doc.Policy)
	var spec autonomy.Service
	count := 0
	for id, s := range a.autonomy.doc.Services {
		if s.Enabled && !s.Removing && cfg.Services[id].Enabled {
			spec = s
			spec.Sources = slices.Clone(s.Sources)
			count++
		}
	}
	a.autonomy.mu.Unlock()
	if count != 1 || autonomyNodeEngine(spec.ExpectedRoute) != "xray" {
		return nil
	}
	service, known := a.autonomyService(spec.ID)
	f := &autonomyXrayFinitePurpose{policy: p, spec: spec, service: defaultRouteCloneCatalogService(service), runtime: r}
	if !known || f.current(a, cfg) != nil {
		return nil
	}
	return f
}

func (f *autonomyXrayFinitePurpose) current(a *App, cfg config.Config) error {
	if f == nil || a == nil || !a.autonomyConsent(f.policy, f.spec) || f.spec.Removing || !f.spec.Enabled || f.spec.AllLAN || len(f.spec.Sources) != 1 || !cfg.Services[f.spec.ID].Enabled || autonomyNodeEngine(selectedRoute(cfg.Services[f.spec.ID])) != "xray" || !wgListBaselineDNS(a.DNS, f.spec.ID) {
		return ErrListScopeChanged
	}
	if f.runtime != nil && (!f.runtime.original() || f.runtime.app != a) {
		return ErrListScopeChanged
	}
	prefix, err := netip.ParsePrefix(f.spec.Sources[0])
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || !prefix.Addr().IsGlobalUnicast() || prefix != prefix.Masked() {
		return ErrListScopeChanged
	}
	actual, known := a.autonomyService(f.spec.ID)
	if !known || !reflect.DeepEqual(actual, f.service) || f.spec.Definition != autonomyDefinition(actual) || len(actual.Domains) != 0 || len(actual.CIDRs) == 0 {
		return ErrListScopeChanged
	}
	for _, raw := range actual.CIDRs {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.Addr().Is4() || p != p.Masked() || !publicfetch.PublicPrefix(p) {
			return ErrListScopeChanged
		}
	}
	for id, s := range cfg.Services {
		if id != f.spec.ID && s.Enabled && selectedRoute(s) != "direct" {
			return ErrListScopeChanged
		}
	}
	return nil
}

type autonomyXrayFiniteAcquire func(context.Context, physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.FiniteIPv4PacketObservation, func(context.Context) error, func() error, error)

func newReviewedAutonomyXrayFiniteDeviceScope(ctx context.Context, a *App, cfg config.Config, source func(context.Context) error, provider *netidentity.Provider, purpose *autonomyXrayFinitePurpose) (context.Context, func() error, error) {
	if provider == nil {
		return nil, nil, ErrListScopeChanged
	}
	var principal *physicalscope.FiniteIPv4PacketPrincipal
	owned, close, err := newAutonomyXrayFiniteDeviceScope(ctx, a, cfg, source, purpose, func(c context.Context, selection physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.FiniteIPv4PacketObservation, func(context.Context) error, func() error, error) {
		var err error
		principal, err = physicalscope.NewReviewedStockNC1812FiniteIPv4PacketPrincipal(c, provider, selection)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return principal.Current, principal.Observation, principal.CurrentRetained, principal.Close, nil
	})
	if err != nil {
		return nil, nil, err
	}
	owned.Value(autonomyDeviceScopeKey{}).(*autonomyDeviceScope).finite.principal = principal
	return owned, close, nil
}

// Private source seam explicitly models I/O. Production borrowing below still
// requires the concrete principal; these callbacks cannot supply that issuer.
func newAutonomyXrayFiniteDeviceScope(ctx context.Context, a *App, cfg config.Config, source func(context.Context) error, purpose *autonomyXrayFinitePurpose, acquire autonomyXrayFiniteAcquire) (context.Context, func() error, error) {
	if ctx == nil || ctx.Value(autonomyDeviceScopeKey{}) != nil || a == nil || a.Store == nil || source == nil || acquire == nil || purpose == nil || !config.CurrentDefaultRouteScopeConsent(cfg) || cfg.NetworkPolicy.Clients.Mode != "selected_devices" || cfg.NetworkPolicy.Clients.NewDevices != "base" || len(cfg.NetworkPolicy.Clients.DeviceIDs) != 1 || len(cfg.NetworkPolicy.Clients.SegmentIDs) != 1 || cfg.NetworkPolicy.Traffic.Mode != "selected_services" {
		return nil, nil, ErrListScopeChanged
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, nil, ErrListScopeChanged
	}
	d := &autonomyDeviceScope{app: a, store: a.Store, original: ctx, policy: config.CloneNetworkPolicy(cfg.NetworkPolicy), consent: config.CloneDefaultRouteConsent(cfg.DefaultRouteConsent), source: source}
	d.self = d
	f := &autonomyXrayFiniteDeviceScope{owner: d, purpose: purpose}
	f.self, d.finite = f, f
	owned := context.WithValue(ctx, autonomyDeviceScopeKey{}, d)
	c, cancel, err := listScopeContext(owned)
	if err != nil {
		return nil, nil, err
	}
	defer cancel()
	err = a.Operations.WithExclusiveContext(c, func() error {
		if err := purpose.current(a, cfg); err != nil {
			return err
		}
		selection, err := d.selection(c)
		if err != nil {
			return err
		}
		f.verify, f.observe, f.retained, d.close, err = acquire(c, d.selection)
		if err != nil || f.verify == nil || f.observe == nil || f.retained == nil || d.close == nil {
			return errors.Join(ErrListScopeChanged, err)
		}
		f.facts = f.observe()
		if f.facts.ReviewID == "" || f.facts.Identity.Validate() != nil || f.facts.Identity.Kind != netidentity.ReviewedSingleInitNet || !reflect.DeepEqual(f.facts.Selection, selection) {
			return ErrListScopeChanged
		}
		if _, err := f.members(purpose.spec, d.policy.Clients); err != nil {
			return err
		}
		return d.current(c)
	})
	if err != nil {
		return nil, nil, errors.Join(err, d.Close())
	}
	return owned, d.Close, nil
}

func (d *autonomyDeviceScope) physicalCurrent(ctx context.Context) error {
	if d.finite != nil {
		f := d.finite
		if !f.original() || f.purpose.current(d.app, d.store.Get()) != nil {
			return ErrListScopeChanged
		}
		if err := f.verify(ctx); err != nil {
			return err
		}
		if !reflect.DeepEqual(f.observe(), f.facts) {
			return ErrListScopeChanged
		}
		return f.purpose.current(d.app, d.store.Get())
	}
	if d.verify == nil || d.snapshot == nil {
		return ErrListScopeChanged
	}
	if err := d.verify(ctx); err != nil {
		return err
	}
	if !reflect.DeepEqual(d.snapshot(), d.facts) {
		return ErrListScopeChanged
	}
	return nil
}

func (f *autonomyXrayFiniteDeviceScope) original() bool {
	return f != nil && f.self == f && f.owner != nil && f.owner.self == f.owner && f.owner.finite == f && f.verify != nil && f.observe != nil && f.retained != nil && f.owner.close != nil && f.owner.verify == nil && f.owner.snapshot == nil && f.owner.observer == nil && f.owner.review == nil && reflect.DeepEqual(f.owner.facts, physicalscope.Snapshot{})
}

func (f *autonomyXrayFiniteDeviceScope) members(s autonomy.Service, clients config.ClientScope) ([]string, error) {
	if !f.original() || f.purpose == nil || len(s.Sources) != 1 || s.ID != f.purpose.spec.ID || s.AllLAN || !slices.Equal(s.Sources, f.purpose.spec.Sources) || clients.Mode != "selected_devices" || clients.NewDevices != "base" || len(clients.DeviceIDs) != 1 || len(clients.SegmentIDs) != 1 || f.facts.Selection.SelectedDevices == nil || !slices.Equal(f.facts.Selection.SelectedDevices.DeviceIDs, clients.DeviceIDs) || !autonomyFiniteExcludedDevicesEqual(f.facts.Selection.SelectedDevices.ExcludedDeviceIDs, clients.ExcludedDeviceIDs) || !slices.Equal(f.facts.Selection.SegmentIDs, clients.SegmentIDs) || len(f.facts.Segments) != 1 {
		return nil, errAutonomyResourceIneligible
	}
	// Native resolution retains intent as supplied, but emits canonical IDs
	// for the observed segment and its devices. Resolve only this SAME single
	// observed segment; keep the original selection/facts unchanged.
	segment := f.facts.Segments[0]
	if segment.ID == "" || clients.SegmentIDs[0] == "" || clients.SegmentIDs[0] != segment.ID && clients.SegmentIDs[0] != segment.NativeName {
		return nil, errAutonomyResourceIneligible
	}
	prefix, err := netip.ParsePrefix(s.Sources[0])
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 {
		return nil, errAutonomyResourceIneligible
	}
	selected := clients.DeviceIDs[0]
	if slices.Contains(clients.ExcludedDeviceIDs, selected) {
		return nil, errAutonomyResourceIneligible
	}
	count := 0
	for _, d := range f.facts.Devices {
		if d.ID != selected {
			continue
		}
		if d.IfIndex <= 0 || d.IfIndex != segment.IfIndex || d.Interface != segment.Interface || d.SegmentID != segment.ID || d.MAC == "" {
			return nil, ErrListScopeChanged
		}
		ipv4 := 0
		for _, raw := range d.Addresses {
			ip, err := netip.ParseAddr(raw)
			if err != nil {
				return nil, ErrListScopeChanged
			}
			if ip.Is4() {
				ipv4++
				if ip != prefix.Addr() {
					return nil, ErrListScopeChanged
				}
			}
		}
		if ipv4 != 1 {
			return nil, ErrListScopeChanged
		}
		count++
	}
	if count != 1 {
		return nil, ErrListScopeChanged
	}
	return []string{selected}, nil
}

// Only order is immaterial. The original complete projection and policy must
// contain the exact same bounded IDs, with no duplicate removal or guessing.
func autonomyFiniteExcludedDevicesEqual(observed, intent []string) bool {
	if len(observed) != len(intent) || len(observed) > 128 {
		return false
	}
	a, b := slices.Clone(observed), slices.Clone(intent)
	slices.Sort(a)
	slices.Sort(b)
	for i := range a {
		if a[i] == "" || b[i] == "" || i > 0 && (a[i] == a[i-1] || b[i] == b[i-1]) {
			return false
		}
	}
	return slices.Equal(a, b)
}

// Closed acquire dispatch. A finite carrier never falls back to a full
// binding, including after revocation, copy, or a failed one-use loan.
func (a *App) autonomyXrayScopeOwner(ctx context.Context) (*ListScopeBinding, *xrayFiniteScopeBinding, error) {
	if ctx == nil {
		return nil, nil, ErrListScopeChanged
	}
	d, ok := ctx.Value(autonomyDeviceScopeKey{}).(*autonomyDeviceScope)
	if !ok || d == nil || d.finite == nil {
		full, err := a.autonomyXrayScope(ctx)
		return full, nil, err
	}
	f := d.finite
	if a == nil || d.app != a || d.self != d || !f.original() || f.principal == nil {
		return nil, nil, ErrListScopeChanged
	}
	return a.borrowAutonomyXrayFiniteScope(ctx, d, f.principal)
}

// Concrete production entry above supplies only the SAME principal acquired
// in this round. The private helper is exercised separately with modeled I/O.
func (a *App) borrowAutonomyXrayFiniteScope(ctx context.Context, d *autonomyDeviceScope, principal *physicalscope.FiniteIPv4PacketPrincipal) (*ListScopeBinding, *xrayFiniteScopeBinding, error) {
	d.mu.Lock()
	if d.app != a || d.self != d || d.finite == nil || !d.finite.original() || d.borrowUsed || d.current(ctx) != nil || principal != d.finite.principal {
		d.mu.Unlock()
		return nil, nil, ErrListScopeChanged
	}
	if principal != nil && principal.Current(ctx) != nil {
		d.mu.Unlock()
		return nil, nil, ErrListScopeChanged
	}
	f := d.finite
	d.borrowUsed, d.borrowed = true, true
	d.mu.Unlock()
	var once sync.Once
	var closeErr error
	release := func() error {
		once.Do(func() {
			d.mu.Lock()
			defer d.mu.Unlock()
			d.borrowed = false
			if d.closed {
				d.closeErr = d.close()
			}
			closeErr = d.closeErr
		})
		return closeErr
	}
	verify := func(c context.Context) error {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.current(c)
	}
	b, err := newXrayFiniteScopeBinding(ctx, a, func(c context.Context, selection physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.FiniteIPv4PacketObservation, func(context.Context) error, func() error, error) {
		want, err := selection(c)
		if err != nil || !reflect.DeepEqual(want, f.facts.Selection) || !reflect.DeepEqual(f.observe(), f.facts) {
			return nil, nil, nil, nil, errors.Join(ErrListScopeChanged, err)
		}
		return verify, f.observe, f.retained, release, nil
	})
	if err != nil {
		return nil, nil, errors.Join(err, release())
	}
	b.principal = principal
	return nil, b, nil
}
