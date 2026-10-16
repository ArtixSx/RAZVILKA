package startuptools

import (
	"context"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

func (r *wgRunner) ReadWGKernelServiceTable(ctx context.Context, expected netidentity.Identity, table, family int, iface string) (int, error) {
	if r == nil {
		return 0, at("WG_ROUTE_SOURCE", nil)
	}
	return r.lease.readWGKernelServiceTable(ctx, r.engine, expected, table, family, iface)
}

func (r *wgInactivityRunner) ReadWGKernelServiceTable(ctx context.Context, expected netidentity.Identity, table, family int, iface string) (int, error) {
	if r == nil {
		return 0, at("WG_ROUTE_SOURCE", nil)
	}
	return r.lease.readWGKernelServiceTable(ctx, r.engine, expected, table, family, iface)
}

func (l *Lease) readWGKernelServiceTable(ctx context.Context, engine string, expected netidentity.Identity, table, family int, iface string) (int, error) {
	if l == nil || ctx == nil || expected.Validate() != nil || engine != "wireguard" && engine != "amneziawg" {
		return 0, at("WG_ROUTE_SOURCE", nil)
	}
	if err := l.retain(ctx); err != nil {
		return 0, err
	}
	defer l.retained.Done()
	if l.provider == nil || expected != l.identity || l.profile.wgEngine != managedListWGProfile && l.profile.wgEngine != engine {
		return 0, at("WG_ROUTE_SOURCE", nil)
	}
	if _, finite := ctx.Deadline(); !finite {
		return 0, at("WG_ROUTE_CONTEXT", nil)
	}
	c, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	stop := context.AfterFunc(l.lifetime, cancel)
	defer stop()
	if err := l.Check(c, expected); err != nil {
		return 0, err
	}
	count, err := physicalscope.ReadWGKernelServiceTable(c, l.provider, l.identity, table, family, iface)
	closing := errors.Join(l.Check(c, expected), c.Err(), l.lifetime.Err())
	if err != nil || closing != nil {
		return 0, errors.Join(err, closing)
	}
	return count, nil
}
