package app

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

type autonomyDeviceScopeKey struct{}

// This read owner lives only in the original coordinator round. It issues no
// path, effect or cleanup permission. Config publication can change a service
// route, but cannot renew the original physical Review or its frozen intent.
type autonomyDeviceScope struct {
	self     *autonomyDeviceScope
	mu       sync.Mutex
	app      *App
	store    *config.Store
	original context.Context
	policy   *config.NetworkPolicy
	consent  *config.DefaultRouteConsent
	facts    physicalscope.Snapshot
	source   func(context.Context) error
	verify   func(context.Context) error
	snapshot func() physicalscope.Snapshot
	close    func() error
	closed   bool
	invalid  bool
	closeErr error
}

func (a *App) autonomyDeviceContext(ctx context.Context, cfg config.Config) (context.Context, func() error, error) {
	if cfg.NetworkPolicy == nil || cfg.NetworkPolicy.Clients.Mode != "selected_devices" {
		return ctx, func() error { return nil }, nil
	}
	if ctx == nil || ctx.Value(autonomyDeviceScopeKey{}) != nil {
		return nil, nil, ErrListScopeChanged
	}
	a.managedListPolicyMu.Lock()
	p := a.managedListPolicy
	a.managedListPolicyMu.Unlock()
	if p == nil || !p.original() || p.closed.Load() || !p.startupReady || p.startupFailure != nil {
		return nil, nil, ErrListScopeChanged
	}
	// Production has one closed acquisition path, retaining the actual original
	// startup provider/control and the Observer/Review opened in THIS round.
	source := func(c context.Context) error {
		if !p.original() || p.closed.Load() || p.control == nil || a.SelfUpdateFiles == nil || !p.control.MatchesControlRoot(a.SelfUpdateFiles.ControlRoot) {
			return ErrListScopeChanged
		}
		ref := p.control.Reference()
		if cfg.DefaultRouteConsent == nil || cfg.DefaultRouteConsent.InstallationID != ref.InstallationID || cfg.DefaultRouteConsent.Sequence != ref.Sequence {
			return ErrListScopeChanged
		}
		return p.control.Current(c)
	}
	return newAutonomyDeviceScope(ctx, a, cfg, source, func(c context.Context, selection physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.Snapshot, func() error, error) {
		observer := physicalscope.NewReviewedStockNC1812(p.provider, selection)
		review, err := observer.Observe(c)
		if err != nil {
			return nil, nil, nil, err
		}
		return func(c context.Context) error { return observer.Verify(c, review) }, review.Snapshot, review.Close, nil
	})
}

// The private acquisition seam models physical facts in source tests only.
// No App option, API payload or persisted image can supply these functions.
func newAutonomyDeviceScope(ctx context.Context, a *App, cfg config.Config, source func(context.Context) error, acquire func(context.Context, physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.Snapshot, func() error, error)) (context.Context, func() error, error) {
	if ctx == nil || a == nil || a.Store == nil || source == nil || acquire == nil || !config.CurrentDefaultRouteScopeConsent(cfg) || cfg.NetworkPolicy.Clients.Mode != "selected_devices" || cfg.NetworkPolicy.Clients.NewDevices != "base" {
		return nil, nil, ErrListScopeChanged
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, nil, ErrListScopeChanged
	}
	d := &autonomyDeviceScope{app: a, store: a.Store, original: ctx, policy: config.CloneNetworkPolicy(cfg.NetworkPolicy), consent: config.CloneDefaultRouteConsent(cfg.DefaultRouteConsent), source: source}
	d.self = d
	owned := context.WithValue(ctx, autonomyDeviceScopeKey{}, d)
	c, cancel, err := listScopeContext(owned)
	if err != nil {
		return nil, nil, err
	}
	defer cancel()
	err = a.Operations.WithExclusiveContext(c, func() error {
		if _, err := d.selection(c); err != nil {
			return err
		}
		var err error
		d.verify, d.snapshot, d.close, err = acquire(c, d.selection)
		if err != nil || d.verify == nil || d.snapshot == nil || d.close == nil {
			return errors.Join(ErrListScopeChanged, err)
		}
		d.facts = d.snapshot()
		if d.facts.ReviewID == "" || d.facts.Identity.Validate() != nil || d.facts.Identity.Kind != netidentity.ReviewedSingleInitNet {
			return ErrListScopeChanged
		}
		return d.current(c)
	})
	if err != nil {
		return nil, nil, errors.Join(err, d.Close())
	}
	return owned, d.Close, nil
}

func (d *autonomyDeviceScope) owner(ctx context.Context) error {
	if d == nil || d.self != d || d.app == nil || d.store == nil || d.app.Store != d.store || ctx == nil || ctx.Value(autonomyDeviceScopeKey{}) != d || d.original == nil || d.original.Err() != nil || ctx.Err() != nil {
		return ErrListScopeChanged
	}
	deadline, finite := ctx.Deadline()
	originalDeadline, originalFinite := d.original.Deadline()
	if !finite || !originalFinite || deadline.After(originalDeadline) || !time.Now().Before(originalDeadline) {
		return ErrListScopeChanged
	}
	// A new operation cannot revive an escaped carrier after original release.
	if err := d.app.Operations.WithExclusiveContext(d.original, func() error { return nil }); err != nil {
		return err
	}
	return d.app.Operations.WithExclusiveContext(ctx, func() error { return nil })
}

func (d *autonomyDeviceScope) sameIntent(cfg config.Config) bool {
	return config.CurrentDefaultRouteScopeConsent(cfg) && !cfg.SafeMode && !cfg.ServiceControl.Stopped && cfg.ServiceControl.EffectiveMode() != "manual" && reflect.DeepEqual(cfg.NetworkPolicy, d.policy) && reflect.DeepEqual(cfg.DefaultRouteConsent, d.consent)
}

// Observer reads selection outside its Provider bracket. This Store callback
// is a closed pure comparison; it does not call Gate, Store or any provider.
func (d *autonomyDeviceScope) selection(ctx context.Context) (physicalscope.Selection, error) {
	if err := d.owner(ctx); err != nil {
		return physicalscope.Selection{}, err
	}
	if err := d.source(ctx); err != nil {
		return physicalscope.Selection{}, err
	}
	cfg := d.store.Get()
	err := d.store.WithResourceExclusionObservation(ctx, cfg, func(config.EffectiveExclusionSet) error {
		if !d.sameIntent(cfg) {
			return ErrListScopeChanged
		}
		return nil
	})
	if err != nil {
		return physicalscope.Selection{}, err
	}
	s := physicalscope.Selection{Revision: d.consent.ApprovalRevision, PolicyRevision: d.policy.Revision, SegmentIDs: slices.Clone(d.policy.Clients.SegmentIDs), SelectedDevices: &physicalscope.SelectedDeviceProjection{DeviceIDs: slices.Clone(d.policy.Clients.DeviceIDs), ExcludedDeviceIDs: slices.Clone(d.policy.Clients.ExcludedDeviceIDs)}}
	slices.Sort(s.SegmentIDs)
	slices.Sort(s.SelectedDevices.DeviceIDs)
	slices.Sort(s.SelectedDevices.ExcludedDeviceIDs)
	return s, d.source(ctx)
}

func (d *autonomyDeviceScope) current(ctx context.Context) error {
	if d.closed || d.invalid || d.verify == nil || d.snapshot == nil {
		return ErrListScopeChanged
	}
	err := d.owner(ctx)
	if err == nil {
		err = d.source(ctx)
	}
	if err == nil {
		err = d.verify(ctx)
	}
	if err == nil && !reflect.DeepEqual(d.snapshot(), d.facts) {
		err = ErrListScopeChanged
	}
	if err == nil {
		err = d.source(ctx)
	}
	if err == nil {
		err = d.owner(ctx)
	}
	if err != nil {
		d.invalid = true
	}
	return err
}

func (d *autonomyDeviceScope) use(ctx context.Context, cfg config.Config, service autonomy.Service, leaf func(context.Context, []string) error) error {
	if d == nil || d.self != d || leaf == nil {
		return ErrListScopeChanged
	}
	c, cancel, err := listScopeContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.sameIntent(cfg) {
		d.invalid = true
		return ErrListScopeChanged
	}
	if err := d.current(c); err != nil {
		return err
	}
	ids, err := autonomyPhysicalDeviceMembers(d.facts, service, d.policy.Clients)
	if err == nil {
		err = leaf(c, ids)
	}
	return errors.Join(err, d.current(c))
}

func (d *autonomyDeviceScope) Close() error {
	if d == nil {
		return nil
	}
	if d.self != d {
		return ErrListScopeChanged
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		if d.close != nil {
			d.closeErr = d.close()
		}
	}
	return d.closeErr
}

// IPs are compared with observed device bindings, never decoded into an
// identity. Broad source prefixes cannot identify a selected client.
func autonomyPhysicalDeviceMembers(facts physicalscope.Snapshot, service autonomy.Service, clients config.ClientScope) ([]string, error) {
	if clients.Mode != "selected_devices" || clients.NewDevices != "base" || service.AllLAN || len(service.Sources) == 0 || len(service.Sources) > 128 || facts.Selection.SelectedDevices == nil {
		return nil, errAutonomyResourceIneligible
	}
	byAddress := map[netip.Addr]string{}
	seen := map[string]bool{}
	for _, device := range facts.Devices {
		if device.ID == "" || seen[device.ID] || device.IfIndex <= 0 || device.Interface == "" || device.SegmentID == "" || len(device.Addresses) == 0 {
			return nil, ErrListScopeChanged
		}
		seen[device.ID] = true
		for _, raw := range device.Addresses {
			address, err := netip.ParseAddr(raw)
			if err != nil || !address.IsGlobalUnicast() || address.Is4In6() || address.Zone() != "" || byAddress[address] != "" {
				return nil, ErrListScopeChanged
			}
			byAddress[address] = device.ID
		}
	}
	var ids []string
	for _, raw := range service.Sources {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() || prefix.Bits() != prefix.Addr().BitLen() {
			return nil, errAutonomyResourceIneligible
		}
		id := byAddress[prefix.Addr()]
		if id == "" || !slices.Contains(clients.DeviceIDs, id) || slices.Contains(clients.ExcludedDeviceIDs, id) {
			return nil, errAutonomyResourceIneligible
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids, nil
}
