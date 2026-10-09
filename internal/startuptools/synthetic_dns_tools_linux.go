//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"slices"
)

func (l *Lease) runSyntheticDNS(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := l.retain(ctx); err != nil {
		return nil, err
	}
	defer l.retained.Done()
	if !l.syntheticDNSIssued() {
		return nil, at("SYNTHETIC_DNS_UNISSUED", nil)
	}
	frozen := slices.Clone(args)
	if name != l.profile.aliases[0] || !syntheticDNSArguments(frozen) {
		return nil, at("SYNTHETIC_DNS_ABI", nil)
	}
	// Reuse the retained original effect implementation: tool/Provider checks
	// and admission at actual Cmd.Start, then exactly one bounded Wait outside
	// those gates. No alternate executor, shell or whole-Wait admission exists.
	return l.policyEffect(ctx, 0, frozen)
}
