//go:build linux && (amd64 || arm64)

package physicalscope

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func readScopeOptions(ctx context.Context) (ScopeOptionsObservation, error) {
	r := unavailableScopeOptions("SOURCE_UNAVAILABLE")
	provider, err := netidentity.NewReviewedStockNC1812Provider(ctx)
	if err != nil {
		return r, err
	}
	err = provider.WithCurrent(ctx, func(c context.Context, identity netidentity.Identity) error {
		if identity.Kind != netidentity.ReviewedSingleInitNet {
			return ErrUnknown
		}
		var in scopeOptionsInput
		var err error
		in.native, err = provider.ReadReviewedStockInterfaces(c)
		if err != nil {
			return err
		}
		in.links, err = dump(c, 18, 0)
		if err != nil {
			return err
		}
		in.addresses, err = dump(c, 22, 0)
		if err != nil {
			return err
		}
		for _, family := range []byte{2, 10} {
			frames, err := dump(c, 26, family)
			if err != nil {
				return err
			}
			in.routes = append(in.routes, frames...)
		}
		r, err = scopeOptionsFromFacts(c, in, observeScopeOptionsBindings)
		return err
	})
	return r, err
}

func observeScopeOptionsBindings(ctx context.Context, segments []Segment) (scopeOptionsBindingFacts, error) {
	families := map[byte][]message{}
	for _, family := range []byte{2, 10} {
		frames, err := dump(ctx, 30, family)
		if err != nil {
			if family == 2 {
				return scopeOptionsBindingFacts{}, at("kernel.bindings.ipv4.dump", err)
			}
			return scopeOptionsBindingFacts{}, at("kernel.bindings.ipv6.dump", err)
		}
		families[family] = frames
	}
	return bindScopeOptionsKernelNeighbors(ctx, segments, families)
}
