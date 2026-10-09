package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/sources"
)

var ErrXrayListSource = errors.New("original Xray list source unavailable or changed")

// XrayListRuntimeSource retains original App, scope, registered adapter, source
// cache and private node owners. Reads and pure compilation create no runtime,
// path health, ingress binding or effect admission. CORE composes these owners
// with its actual runtime and joined compensation under the SAME operation.
type XrayListRuntimeSource struct {
	self                                                *XrayListRuntimeSource
	mu                                                  sync.Mutex
	closed                                              atomic.Bool
	invalid                                             bool
	closeDone                                           chan struct{}
	closeErr                                            error
	ctx                                                 context.Context
	cancel                                              context.CancelFunc
	app                                                 *App
	store                                               *config.Store
	manager                                             *dataplane.Manager
	files                                               *SelfUpdateFiles
	nodes                                               *nodestore.Store
	sources                                             *sources.Manager
	custom                                              *customservices.Manager
	dns                                                 *dnscontrol.Manager
	scope                                               *ListScopeBinding
	root, catalog, service, selected, wan, materialHash string
	expected                                            config.Config
	frozen                                              catalog.Service
	identity                                            netidentity.Identity
	control                                             *operationgate.ControlEpochReview
	registration                                        *dataplane.XrayRegistrationReview
	cidrs                                               *sources.ServiceCIDRReview
	node                                                *dataplane.NodeDefaultSourceReview
}

// Detached comparison data only. No constructor accepts this observation, and
// no Paths, Ready, ACTIVE or profile-generation permission is emitted.
type XrayListSourceObservation struct {
	ServiceID, Selected, Resolved, ProbeURL, WANProfile, RouteMaterialSHA256 string
	Service                                                                  catalog.Service
	Sources                                                                  sources.ServiceCIDRObservation
	Node                                                                     dataplane.NodeDefaultSourceReference
	NetworkIdentity                                                          netidentity.Identity
}

func (*XrayListRuntimeSource) String() string   { return "[private original Xray App list source]" }
func (*XrayListRuntimeSource) GoString() string { return "[private original Xray App list source]" }

// original is the SAME adapter returned by CORE's actual factory and registered
// in this App's Manager. serviceID selects existing local intent; it supplies no
// destinations, expected provenance, node material or permission callback.
func (a *App) ReviewXrayListRuntimeSource(ctx context.Context, scope *ListScopeBinding, serviceID string, original *dataplane.ProxyTunnelAdapter) (*XrayListRuntimeSource, error) {
	if xrayListSourceContext(ctx) != nil || a == nil || a.Store == nil || a.Dataplane == nil || a.Nodes == nil || a.Sources == nil || a.SelfUpdateFiles == nil ||
		scope == nil || scope.self != scope || scope.app != a || scope.store != a.Store {
		return nil, ErrXrayListSource
	}
	lifetime, cancel := context.WithCancel(ctx)
	r := &XrayListRuntimeSource{ctx: lifetime, cancel: cancel, app: a, store: a.Store, manager: a.Dataplane, files: a.SelfUpdateFiles,
		nodes: a.Nodes, sources: a.Sources, custom: a.CustomServices, dns: a.DNS, scope: scope, root: a.SelfUpdateFiles.ControlRoot,
		service: serviceID, closeDone: make(chan struct{})}
	r.self = r
	keep := false
	defer func() {
		if !keep {
			_ = r.Close()
		}
	}()
	err := scope.use(ctx, func(c context.Context) error {
		r.expected = r.store.Get()
		state, exists := r.expected.Services[serviceID]
		if !exists || !state.Enabled || !wgListBaselineDNS(r.dns, serviceID) {
			return ErrXrayListSource
		}
		r.selected = selectedRoute(state)
		if !strings.HasPrefix(r.selected, "xray:node-") {
			return ErrXrayListSource
		}
		actual := a.catalogSnapshot()
		r.catalog = applyReviewHash(actual)
		matches := 0
		for _, s := range actual.Services {
			if s.ID == serviceID {
				r.frozen = defaultRouteCloneCatalogService(s)
				matches++
			}
		}
		if matches != 1 || len(r.frozen.Domains) != 0 || len(r.frozen.CIDRs) == 0 || len(r.frozen.SourceRefs) == 0 {
			return ErrXrayListSource
		}
		var err error
		r.frozen, err = dataplane.FrozenProbeService(dataplane.Route{LogicalServiceID: serviceID, ProbeService: &r.frozen, ProbeURL: r.frozen.ProbeURL})
		if err != nil {
			return err
		}
		r.cidrs, err = r.sources.ReviewServiceCIDRs(c, serviceID, r.frozen.SourceRefs)
		if err != nil {
			return err
		}
		observation, err := r.cidrs.Observation(c)
		if err != nil || !slices.Equal(r.frozen.CIDRs, observation.CIDRs) || !xrayListLiteralProbeInCIDRs(r.frozen) {
			return errors.Join(ErrXrayListSource, err)
		}
		r.registration, err = r.manager.ReviewXrayRegistration(c, original)
		if err != nil {
			return err
		}
		r.control, err = a.Operations.ReviewControlEpoch(c, r.root)
		if err != nil {
			return err
		}
		r.wan, err = a.freshNetworkProfile(c)
		if err != nil || r.wan != scope.networkID {
			return errors.Join(ErrXrayListSource, err)
		}
		r.identity = scope.facts.Identity
		r.node, err = dataplane.ReviewNodeDefaultSource(c, r.nodes, r.selected)
		if err != nil {
			return err
		}
		r.materialHash, err = r.currentNodeMaterial(c)
		return err
	})
	if err != nil {
		return nil, errors.Join(ErrXrayListSource, err)
	}
	if err := r.Current(ctx); err != nil {
		return nil, err
	}
	keep = true
	return r, nil
}

func xrayListSourceContext(ctx context.Context) error {
	if ctx == nil {
		return ErrXrayListSource
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrXrayListSource, err)
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrXrayListSource
	}
	return nil
}

// Hostname probes retain the existing finite CIDR DNS pin admission in the
// concrete runtime. This source performs no DNS. Literal probes must already
// belong to the complete canonical list; no hostname fallback is introduced.
func xrayListLiteralProbeInCIDRs(service catalog.Service) bool {
	u, err := url.Parse(service.ProbeURL)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return true
	}
	if ip.Is4In6() || ip.Zone() != "" {
		return false
	}
	for _, raw := range service.CIDRs {
		p, err := netip.ParsePrefix(raw)
		if err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *XrayListRuntimeSource) currentApp() error {
	if r.closed.Load() || r.app == nil || r.app.Store != r.store || r.app.Dataplane != r.manager || r.app.Nodes != r.nodes || r.app.Sources != r.sources ||
		r.app.CustomServices != r.custom || r.app.DNS != r.dns || r.app.SelfUpdateFiles != r.files || r.files.ControlRoot != r.root ||
		r.scope.self != r.scope || r.scope.app != r.app || r.scope.store != r.store || !reflect.DeepEqual(r.store.Get(), r.expected) ||
		applyReviewHash(r.app.catalogSnapshot()) != r.catalog || !wgListBaselineDNS(r.dns, r.service) {
		return ErrXrayListSource
	}
	return nil
}

// Check exact existing Xray/service/WAN eligibility, then compile privately.
// Generation/material bookends prevent borrowing another revision's PASS.
func (r *XrayListRuntimeSource) currentNodeMaterial(ctx context.Context) (string, error) {
	if err := r.node.Current(ctx); err != nil {
		return "", err
	}
	ref := r.node.Reference()
	resolved, err := r.nodes.ResolveRouteForEngine(ctx, "xray", ref.NodeID, r.service, r.wan, "", time.Time{}, time.Now().UTC())
	if err != nil || resolved.NodeID != ref.NodeID || resolved.Route != r.selected {
		return "", errors.Join(ErrXrayListSource, err)
	}
	material, err := r.nodes.MaterializeXray(ctx, []nodestore.RouteBinding{{ServiceID: r.service, NodeID: ref.NodeID, NetworkProfile: r.wan, Destinations: slices.Clone(r.frozen.CIDRs)}}, time.Now().UTC())
	defer clear(material.Config)
	if err != nil || material.EngineID != "xray" || len(material.Config) == 0 {
		return "", errors.Join(ErrXrayListSource, err)
	}
	digest := sha256.Sum256(material.Config)
	if err := r.node.Current(ctx); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func (r *XrayListRuntimeSource) currentLocked(ctx context.Context) error {
	if r.invalid || r.control == nil || r.registration == nil || r.cidrs == nil || r.node == nil {
		return ErrXrayListSource
	}
	if err := r.currentApp(); err != nil {
		return err
	}
	// Preserve the fresh caller's values, but cancellation/deadline of the
	// original operation and Close also stop every synchronous source read.
	deadline, _ := r.ctx.Deadline()
	c, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(r.ctx, cancel)
	defer func() { stop(); cancel() }()
	return r.app.Operations.WithExclusiveContext(r.ctx, func() error {
		return r.scope.use(c, func(c context.Context) error {
			if err := r.currentApp(); err != nil {
				return err
			}
			if err := r.control.Current(c); err != nil {
				return err
			}
			if err := r.registration.Current(c); err != nil {
				return err
			}
			if err := r.cidrs.Current(c); err != nil {
				return err
			}
			wan, err := r.app.freshNetworkProfile(c)
			if err != nil || wan != r.wan || r.scope.facts.Identity != r.identity {
				return errors.Join(ErrXrayListSource, err)
			}
			material, err := r.currentNodeMaterial(c)
			if err != nil || material != r.materialHash {
				return errors.Join(ErrXrayListSource, err)
			}
			if err := r.cidrs.Current(c); err != nil {
				return err
			}
			if err := r.registration.Current(c); err != nil {
				return err
			}
			if err := r.currentApp(); err != nil {
				return err
			}
			return r.control.Current(c)
		})
	})
}

func (r *XrayListRuntimeSource) Current(ctx context.Context) error {
	if r == nil || r.self != r || xrayListSourceContext(ctx) != nil || r.closed.Load() {
		return ErrXrayListSource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	err := r.currentLocked(ctx)
	if err != nil {
		r.invalid = true
	}
	return err
}

func (r *XrayListRuntimeSource) Observation(ctx context.Context) (XrayListSourceObservation, error) {
	if r == nil || r.self != r || xrayListSourceContext(ctx) != nil || r.closed.Load() {
		return XrayListSourceObservation{}, ErrXrayListSource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.currentLocked(ctx); err != nil {
		r.invalid = true
		return XrayListSourceObservation{}, err
	}
	observation, err := r.cidrs.Observation(ctx)
	if err != nil {
		r.invalid = true
		return XrayListSourceObservation{}, err
	}
	if err := r.currentLocked(ctx); err != nil {
		r.invalid = true
		return XrayListSourceObservation{}, err
	}
	return XrayListSourceObservation{ServiceID: r.service, Selected: r.selected, Resolved: r.selected, ProbeURL: r.frozen.ProbeURL, WANProfile: r.wan,
		RouteMaterialSHA256: r.materialHash, Service: defaultRouteCloneCatalogService(r.frozen), Sources: observation, Node: r.node.Reference(), NetworkIdentity: r.identity}, nil
}

// Close cancels and joins reads before closing only this capture's handles.
// Shared App/scope/Nodes/Sources and the registered runtime remain owned by CORE.
func (r *XrayListRuntimeSource) Close() error {
	if r == nil || r.self != r {
		return ErrXrayListSource
	}
	if !r.closed.CompareAndSwap(false, true) {
		<-r.closeDone
		return r.closeErr
	}
	r.cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	defer close(r.closeDone)
	if r.registration != nil {
		r.closeErr = r.registration.Close()
	}
	if r.cidrs != nil {
		r.closeErr = errors.Join(r.closeErr, r.cidrs.Close())
	}
	if r.control != nil {
		r.closeErr = errors.Join(r.closeErr, r.control.Close())
	}
	return r.closeErr
}
