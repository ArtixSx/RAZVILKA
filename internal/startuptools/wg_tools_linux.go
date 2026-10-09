//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"os"
	"slices"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func (r *heldReview) captureWG(ctx context.Context) error {
	if r.profile.wgEngine == "" {
		return ctx.Err()
	}
	primary := 0
	if r.profile.wgEngine == "amneziawg" {
		primary = 1
	} else if r.profile.wgEngine != "wireguard" {
		return at("WG_PROFILE", nil)
	}
	for i, alias := range r.profile.wgAliases {
		if alias == "" {
			return at("WG_PROFILE", nil)
		}
		if _, err := os.Lstat(alias); errors.Is(err, os.ErrNotExist) && i != primary {
			if err := r.missing(alias); err != nil {
				return err
			}
			continue
		}
		image, err := r.image(ctx, alias, entryRole)
		if err != nil {
			return at("WG_IMAGE", err)
		}
		r.wgEntry[i] = image
	}
	return ctx.Err()
}

func acquireWG(ctx context.Context, provider *netidentity.Provider, p profile) (*Lease, error) {
	l, err := acquire(ctx, provider, p)
	if err != nil {
		return nil, err
	}
	c, cancel := context.WithTimeout(l.lifetime, operationTimeout)
	defer cancel()
	err = func() error {
		if err := l.lock(c); err != nil {
			return err
		}
		defer l.unlock()
		return provider.WithCurrent(c, func(held context.Context, actual netidentity.Identity) error {
			if actual != l.identity {
				return at("WG_VERSION_IDENTITY", nil)
			}
			for i, image := range l.review.wgEntry {
				if image == nil {
					continue
				}
				data, err := l.execute(held, i+3, 256, "--version")
				if err != nil || !validWGVersion(i, data) {
					return at("WG_VERSION", err)
				}
			}
			return held.Err()
		})
	}()
	if err != nil || c.Err() != nil {
		_ = l.Close()
		return nil, at("WG_ACQUIRE", errors.Join(err, c.Err()))
	}
	return l, nil
}

func (l *Lease) runWG(ctx context.Context, engine, name string, args ...string) ([]byte, error) {
	if err := l.retain(ctx); err != nil {
		return nil, err
	}
	defer l.retained.Done()
	if l.review == nil || l.profile.wgEngine == "" || l.digest == "" || l.provider == nil || !boundedArguments(args) {
		return nil, at("WG_UNISSUED", nil)
	}
	index := -1
	for i, alias := range l.profile.aliases {
		if name == alias {
			index = i
		}
	}
	if name == l.profile.ipAlias {
		index = 2
	}
	for i, image := range l.review.wgEntry {
		if image != nil && name == image.path {
			index = i + 3
		}
	}
	frozen := slices.Clone(args)
	if index < 0 || !wgArguments(index, engine, frozen) {
		return nil, at("WG_ABI", nil)
	}
	// Every native WG RPC, including readback, uses the original owner's
	// admission. The existing policy producer owns the actual held-fd Start,
	// short tool/Provider gate, cancellation and exactly one Wait outside it.
	return l.policyEffect(ctx, index, frozen)
}
