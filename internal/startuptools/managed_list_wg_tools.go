package startuptools

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// ManagedListWGCommandTools observes both optional engines under one original
// lease gate, with original Provider checks before and after the projection.
// All original IP/xtables versions execute from held FDs, with their existing
// complete image checks. The
// final complete image/absence check and closing identity precede publication.
// A missing primary remains unavailable; it is never replaced by another CLI.
func (l *Lease) ManagedListWGCommandTools(ctx context.Context, expected netidentity.Identity) (map[string]dataplane.WGCommandTools, error) {
	return l.managedListWGCommandTools(ctx, expected, l.managedListWGObservation)
}

// The private observation seam is used only by explicit portable models. The
// public production entry above always supplies the closed original reader;
// no App option, request, descriptor or saved image can replace that reader.
func (l *Lease) managedListWGCommandTools(ctx context.Context, expected netidentity.Identity, observe func(context.Context, netidentity.Identity, func(context.Context) error) error) (map[string]dataplane.WGCommandTools, error) {
	c, cancel, err := boundedReadContext(ctx)
	if err != nil {
		return nil, at("WG_STARTUP_CONTEXT", err)
	}
	defer cancel()
	if observe == nil || expected.Validate() != nil {
		return nil, at("WG_STARTUP_OWNER", nil)
	}
	if err := l.retain(c); err != nil {
		return nil, at("WG_STARTUP_OWNER", err)
	}
	defer l.retained.Done()
	if err := l.lock(c); err != nil {
		return nil, at("WG_STARTUP_OWNER", err)
	}
	defer l.unlock()
	stop := context.AfterFunc(l.lifetime, cancel)
	defer stop()
	if l.profile.wgEngine != managedListWGProfile || l.review == nil || l.review.ipEntry == nil || l.digest == "" || l.provider == nil || l.identity != expected || l.review.profile.wgEngine != l.profile.wgEngine || l.review.profile.wgAliases != l.profile.wgAliases || l.review.profile.ipAlias != l.profile.ipAlias || l.review.profile.aliases != l.profile.aliases {
		return nil, at("WG_STARTUP_OWNER", nil)
	}
	var descriptors map[string]dataplane.WGCommandTools
	err = observe(c, expected, func(held context.Context) error {
		if err := l.review.wgAbsencesCurrent(held); err != nil {
			return at("WG_STARTUP_DESCRIPTORS", err)
		}
		descriptors = make(map[string]dataplane.WGCommandTools, 2)
		for i, engine := range []string{"wireguard", "amneziawg"} {
			if l.review.wgEntry[i] == nil {
				continue // Only the original, freshly checked absence permits this.
			}
			descriptor, err := l.wgCommandToolsHeld(held, engine)
			if err != nil {
				return at("WG_STARTUP_DESCRIPTORS", err)
			}
			descriptors[engine] = descriptor
		}
		return held.Err()
	})
	if err != nil || c.Err() != nil || l.lifetime.Err() != nil || l.closed.Load() {
		return nil, at("WG_STARTUP_OBSERVATION", errors.Join(err, c.Err(), l.lifetime.Err()))
	}
	return descriptors, nil
}

// Called only while the original tool gate is retained. Each current check
// closes its actual Provider bracket; use performs no Provider or Gate reentry.
func (l *Lease) managedListWGObservation(ctx context.Context, expected netidentity.Identity, use func(context.Context) error) error {
	if err := l.current(ctx, expected, true); err != nil {
		return at("WG_STARTUP_OPEN_CURRENT", err)
	}
	useErr := use(ctx)
	closingErr := l.current(ctx, expected, false)
	if closingErr != nil {
		closingErr = at("WG_STARTUP_CLOSE_CURRENT", closingErr)
	}
	return errors.Join(useErr, closingErr, ctx.Err())
}
