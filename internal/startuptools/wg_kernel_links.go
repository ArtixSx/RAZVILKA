package startuptools

import (
	"context"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// This is the same private startup source that owns the WG inactivity reads.
// It keeps its actual held tool review alive while the existing kernel reader
// runs under that source's original Provider. No CLI/path/DTO fallback exists.
func (r *wgInactivityRunner) ReadWGKernelLinks(ctx context.Context, expected netidentity.Identity) ([]physicalscope.WGKernelLink, error) {
	if r == nil || r.lease == nil || ctx == nil || expected.Validate() != nil || r.engine != "wireguard" && r.engine != "amneziawg" {
		return nil, at("WG_LINK_SOURCE", nil)
	}
	l := r.lease
	if err := l.retain(ctx); err != nil {
		return nil, err
	}
	defer l.retained.Done()
	if l.provider == nil || expected != l.identity || l.profile.wgEngine != managedListWGProfile && l.profile.wgEngine != r.engine {
		return nil, at("WG_LINK_SOURCE", nil)
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, at("WG_LINK_CONTEXT", nil)
	}
	c, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	stop := context.AfterFunc(l.lifetime, cancel)
	defer stop()
	if err := l.Check(c, expected); err != nil {
		return nil, err
	}
	links, err := physicalscope.ReadWGKernelLinks(c, l.provider, l.identity)
	closing := errors.Join(l.Check(c, expected), c.Err(), l.lifetime.Err())
	if err != nil || closing != nil {
		return nil, errors.Join(err, closing)
	}
	return links, nil
}
