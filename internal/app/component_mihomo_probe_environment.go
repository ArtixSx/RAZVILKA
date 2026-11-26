package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"slices"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

// Negative observations only: neither this guard nor its DNS data grants a
// process, route, or installed-component capability.
type mihomoProbeEnvironment struct {
	app       *App
	store     *config.Store
	cfg       config.Config
	catalog   catalog.Catalog
	service   catalog.Service
	network   string
	fresh     func(context.Context) (string, error)
	host      string
	addresses []netip.Addr
}

func newMihomoProbeEnvironment(ctx context.Context, a *App, cfg config.Config, service catalog.Service) (*mihomoProbeEnvironment, error) {
	e := &mihomoProbeEnvironment{app: a, store: a.Store, cfg: cfg, catalog: a.catalogSnapshot(), service: service, fresh: a.FreshProfile}
	e.catalog.Services = append([]catalog.Service(nil), e.catalog.Services...)
	for i := range e.catalog.Services {
		e.catalog.Services[i] = defaultRouteCloneCatalogService(e.catalog.Services[i])
	}
	known := false
	for _, actual := range e.catalog.Services {
		if actual.ID == service.ID && reflect.DeepEqual(actual, service) {
			known = true
		}
	}
	if !known {
		return nil, dataplane.ErrReviewChanged
	}
	if e.fresh == nil {
		e.fresh = func(c context.Context) (string, error) { p, err := systemprobe.FreshWANProfile(c); return p.ID, err }
	}
	var err error
	e.network, err = e.fresh(ctx)
	if err != nil || !systemprobe.ValidWANProfileID(e.network) {
		return nil, errors.Join(err, dataplane.ErrReviewChanged)
	}
	return e, e.current(ctx)
}

func (e *mihomoProbeEnvironment) current(ctx context.Context) error {
	if ctx == nil {
		return dataplane.ErrReviewChanged
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if e.app.Store != e.store || !reflect.DeepEqual(e.catalog, e.app.catalogSnapshot()) {
		return dataplane.ErrReviewChanged
	}
	network, err := e.fresh(ctx)
	if err != nil || network != e.network {
		return errors.Join(err, dataplane.ErrReviewChanged)
	}
	if err := e.app.nodeResourceExclusionAdmission(ctx, e.cfg, e.service, "", netip.Addr{}); err != nil {
		return err
	}
	if e.host != "" {
		addresses, err := e.resolve(ctx, e.host)
		if err != nil || !slices.Equal(addresses, e.addresses) {
			return errors.Join(err, dataplane.ErrReviewChanged)
		}
	}
	network, err = e.fresh(ctx)
	if err != nil || network != e.network || e.app.Store != e.store || !reflect.DeepEqual(e.catalog, e.app.catalogSnapshot()) {
		return errors.Join(err, dataplane.ErrReviewChanged)
	}
	return e.app.nodeResourceExclusionAdmission(ctx, e.cfg, e.service, "", netip.Addr{})
}

func (e *mihomoProbeEnvironment) resource(ctx context.Context, host string, address netip.Addr) error {
	if err := e.current(ctx); err != nil {
		return err
	}
	return e.app.nodeResourceExclusionAdmission(ctx, e.cfg, e.service, host, address)
}

func (e *mihomoProbeEnvironment) endpoint(ctx context.Context, host string) (netip.Addr, error) {
	if err := e.resource(ctx, host, netip.Addr{}); err != nil {
		return netip.Addr{}, err
	}
	addresses, err := e.resolve(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	e.host, e.addresses = host, addresses
	return addresses[0], e.current(ctx)
}

func (e *mihomoProbeEnvironment) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	for i, ip := range addresses {
		ip = ip.Unmap()
		addresses[i] = ip
		if !ip.Is4() || !publicfetch.PublicAddress(ip) {
			return nil, dataplane.ErrNodeResourceDenied
		}
		if err := e.app.nodeResourceExclusionAdmission(ctx, e.cfg, e.service, host, ip); err != nil {
			return nil, err
		}
	}
	if len(addresses) == 0 {
		return nil, dataplane.ErrNodeResourceDenied
	}
	slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(addresses), nil
}
