package app

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// WGListRuntimeSource retains actual App/Store/catalog/profile/physical/tool
// owners for one numeric-endpoint, literal-IP source capture. This emits no
// Paths, ProfileGeneration, Ready or ACTIVE permission. CORE must compose its
// original capture with the SAME scope/Manager through joined compensation.
type WGListRuntimeSource struct {
	self                                        *WGListRuntimeSource
	mu                                          sync.Mutex
	closed                                      atomic.Bool
	closeDone                                   chan struct{}
	closeErr                                    error
	invalid                                     bool
	app                                         *App
	store                                       *config.Store
	manager                                     *dataplane.Manager
	files                                       *SelfUpdateFiles
	dns                                         *dnscontrol.Manager
	root                                        string
	scope                                       *ListScopeBinding
	expected                                    config.Config
	catalog, service, selected, resolved, probe string
	identity                                    netidentity.Identity
	control                                     *operationgate.ControlEpochReview
	reader                                      *dataplane.WGSourceReadReview
	profile                                     *dataplane.WGSourceProfileCapture
	wan                                         dataplane.WGEndpointState
}

type WGListSourceObservation struct {
	ServiceID, Selected, Resolved, ProbeURL string
	Profile                                 dataplane.WGSourceProfileObservation
	Endpoint                                dataplane.WGEndpointState
	NetworkIdentity                         netidentity.Identity
}

func (*WGListRuntimeSource) String() string   { return "[private original WG App source capture]" }
func (*WGListRuntimeSource) GoString() string { return "[private original WG App source capture]" }

// serviceID selects an actual existing config/catalog entry only. No request
// profile, endpoint, snapshot, hash, runner or permission callback is accepted.
func (a *App) ReviewWGListRuntimeSource(ctx context.Context, scope *ListScopeBinding, serviceID string) (*WGListRuntimeSource, error) {
	if a == nil || a.Store == nil || a.Dataplane == nil || a.SelfUpdateFiles == nil || scope == nil || scope.self != scope || scope.app != a || scope.store != a.Store || ctx == nil {
		return nil, dataplane.ErrWGOperationOwner
	}
	if _, err := scope.Observe(ctx); err != nil {
		return nil, err
	}
	if !wgListBaselineDNS(a.DNS, serviceID) {
		return nil, ErrDefaultRouteCapability
	}
	cfg := a.Store.Get()
	state, exists := cfg.Services[serviceID]
	if !exists || !state.Enabled {
		return nil, ErrDefaultRouteCapability
	}
	selected, engine, profile := selectedRoute(state), "", "main"
	switch {
	case selected == "wireguard":
		engine = "wireguard"
	case strings.HasPrefix(selected, "wireguard:"):
		engine, profile = "wireguard", strings.TrimPrefix(selected, "wireguard:")
		if profile == "" || profile == "main" {
			return nil, ErrDefaultRouteCapability
		}
	case selected == "amneziawg":
		engine = "amneziawg"
	default:
		return nil, ErrDefaultRouteCapability
	}
	probe := ""
	for _, service := range a.catalogSnapshot().Services {
		if service.ID != serviceID {
			continue
		}
		if len(service.Domains) != 0 || len(service.CIDRs) == 0 || service.ProbeURL == "" {
			return nil, ErrDefaultRouteCapability
		}
		for _, cidr := range service.CIDRs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil || prefix.Masked().String() != cidr {
				return nil, ErrDefaultRouteCapability
			}
		}
		probe = service.ProbeURL
	}
	if probe == "" {
		return nil, ErrDefaultRouteCapability
	}
	r := &WGListRuntimeSource{app: a, store: a.Store, manager: a.Dataplane, files: a.SelfUpdateFiles, dns: a.DNS, root: a.SelfUpdateFiles.ControlRoot, scope: scope, expected: cfg, catalog: applyReviewHash(a.catalogSnapshot()), service: serviceID, selected: selected, resolved: engine, probe: probe, identity: scope.facts.Identity, closeDone: make(chan struct{})}
	r.self = r
	keep := false
	defer func() {
		if !keep {
			_ = r.Close()
		}
	}()
	var err error
	r.control, err = a.Operations.ReviewControlEpoch(ctx, r.root)
	if err != nil {
		return nil, err
	}
	r.reader, err = dataplane.ReviewWGSourceRead(ctx, a.Dataplane, r.control, engine)
	if err != nil {
		return nil, err
	}
	actual, err := r.reader.NetworkIdentity(ctx)
	if err != nil || actual != r.identity {
		return nil, errors.Join(dataplane.ErrWGOperationOwner, err)
	}
	r.profile, err = r.reader.CaptureProfile(ctx, profile)
	if err != nil {
		return nil, err
	}
	observation, err := r.profile.Observation(ctx)
	if err != nil {
		return nil, err
	}
	if profile != "main" {
		if state.WireGuardProfileRevision != observation.Revision {
			return nil, dataplane.ErrReviewChanged
		}
		r.resolved = engine + ":" + profile
	}
	r.wan, err = r.reader.ObserveNumericEndpoint(ctx, r.profile)
	if err != nil {
		return nil, err
	}
	if err := r.Current(ctx); err != nil {
		return nil, err
	}
	keep = true
	return r, nil
}

func (r *WGListRuntimeSource) Current(ctx context.Context) error {
	if r == nil || r.self != r || ctx == nil || r.closed.Load() {
		return dataplane.ErrWGOperationOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.invalid {
		return dataplane.ErrWGOperationOwner
	}
	err := r.current(ctx)
	if err != nil {
		r.invalid = true
	}
	return err
}
func (r *WGListRuntimeSource) current(ctx context.Context) error {
	if err := r.currentApp(); err != nil {
		return err
	}
	if _, err := r.scope.Observe(ctx); err != nil {
		return err
	}
	if err := r.control.Current(ctx); err != nil {
		return err
	}
	if err := r.profile.Current(ctx); err != nil {
		return err
	}
	wan, err := r.reader.ObserveNumericEndpoint(ctx, r.profile)
	if err != nil || !sameWGListSourceWAN(r.wan, wan) {
		return errors.Join(dataplane.ErrWGOperationOwner, err)
	}
	if _, err := r.scope.Observe(ctx); err != nil {
		return err
	}
	if err := r.currentApp(); err != nil {
		return err
	}
	return r.control.Current(ctx)
}

func (r *WGListRuntimeSource) currentApp() error {
	if r.closed.Load() || r.app == nil || r.store == nil || r.files == nil || r.scope == nil || r.app.Store != r.store || r.app.Dataplane != r.manager || r.app.SelfUpdateFiles != r.files || r.app.DNS != r.dns || r.files.ControlRoot != r.root || r.scope.app != r.app || r.scope.store != r.store || !reflect.DeepEqual(r.store.Get(), r.expected) || applyReviewHash(r.app.catalogSnapshot()) != r.catalog || r.profile == nil || r.reader == nil || r.control == nil {
		return dataplane.ErrWGOperationOwner
	}
	if !wgListBaselineDNS(r.dns, r.service) {
		return ErrDefaultRouteCapability
	}
	return nil
}

func wgListBaselineDNS(dns *dnscontrol.Manager, service string) bool {
	if dns == nil {
		return true
	}
	actual := dns.Snapshot()
	selected := actual.ServiceApplied[service]
	return actual.Applied.ProfileID == "automatic" && (selected == "" || selected == "automatic")
}
func sameWGListSourceWAN(a, b dataplane.WGEndpointState) bool {
	return a.Original == b.Original && a.Endpoint == b.Endpoint && a.Device == b.Device && a.Gateway == b.Gateway && a.Source == b.Source && a.Priority == b.Priority && a.Mark == b.Mark && a.Table == b.Table && a.Metric == b.Metric && a.ExpiresAt.IsZero() && b.ExpiresAt.IsZero()
}

func (r *WGListRuntimeSource) Observation(ctx context.Context) (WGListSourceObservation, error) {
	if err := r.Current(ctx); err != nil {
		return WGListSourceObservation{}, err
	}
	profile, err := r.profile.Observation(ctx)
	if err != nil {
		return WGListSourceObservation{}, err
	}
	if err := r.Current(ctx); err != nil {
		return WGListSourceObservation{}, err
	}
	return WGListSourceObservation{ServiceID: r.service, Selected: r.selected, Resolved: r.resolved, ProbeURL: r.probe, Profile: profile, Endpoint: r.wan, NetworkIdentity: r.identity}, nil
}

// Close owns only this source's inspection/control handles. The calling CORE
// scope and actual startup lease remain alive until their joined consumers end.
func (r *WGListRuntimeSource) Close() error {
	if r == nil || r.self != r {
		return dataplane.ErrWGOperationOwner
	}
	if !r.closed.CompareAndSwap(false, true) {
		<-r.closeDone
		return r.closeErr
	}
	defer close(r.closeDone)
	var err error
	if r.reader != nil {
		err = r.reader.Close()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.control != nil {
		r.control.Close()
	}
	r.closeErr = err
	return r.closeErr
}
