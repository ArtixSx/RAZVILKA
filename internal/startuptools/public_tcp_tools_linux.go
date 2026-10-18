//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"slices"
)

func (l *Lease) runPublicTCP(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := l.retain(ctx); err != nil {
		return nil, err
	}
	defer l.retained.Done()
	if !l.publicTCPIssued() {
		return nil, at("PUBLIC_TCP_UNISSUED", nil)
	}
	index := -1
	if name == l.profile.aliases[0] {
		index = 0
	}
	if name == l.profile.ipAlias {
		index = 2
	}
	frozen := slices.Clone(args)
	if !publicTCPArguments(index, frozen) {
		return nil, at("PUBLIC_TCP_ABI", nil)
	}
	return l.policyEffect(ctx, index, frozen)
}
