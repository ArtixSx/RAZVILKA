package dataplane

import (
	"context"
	"errors"
	"strings"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// NewScopedDNSInactivityKernelCheck binds the DNS consumer to the accepted
// common collector. Startup must hold its admitted tool descriptor throughout
// each call and use the concrete reviewed provider required by that collector.
// No snapshot is cached. A nil/zero collector remains an explicit refusal.
func NewScopedDNSInactivityKernelCheck(inventory *BackendInventory) func(context.Context, netidentity.Identity) error {
	if inventory == nil {
		return scopedDNSInactiveBackendCheck(nil)
	}
	return scopedDNSInactiveBackendCheck(inventory.Read)
}

// Private read seam only for models using the common owner's fixture collector.
func scopedDNSInactiveBackendCheck(read func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error)) func(context.Context, netidentity.Identity) error {
	return func(ctx context.Context, identity netidentity.Identity) error {
		if ctx == nil || ctx.Err() != nil || identity.Validate() != nil || read == nil {
			if ctx != nil {
				return errors.Join(ErrScopedDNSRuntimeInactive, ctx.Err())
			}
			return ErrScopedDNSRuntimeInactive
		}
		snapshot, err := read(ctx, identity)
		if err != nil {
			return errors.Join(ErrScopedDNSRuntimeInactive, err)
		}
		if snapshot.Scope.Network != identity {
			return ErrScopedDNSRuntimeInactive
		}
		if err := snapshot.RequireComplete(); err != nil {
			return errors.Join(ErrScopedDNSRuntimeInactive, err)
		}
		for _, row := range snapshot.Rows {
			if err := ctx.Err(); err != nil {
				return errors.Join(ErrScopedDNSRuntimeInactive, err)
			}
			if err := CheckScopedDNSInactiveRule(row.Family, row.Table, row.Tokens); err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(ErrScopedDNSRuntimeInactive, err)
		}
		return nil
	}
}

// CheckScopedDNSInactiveRule is a pure consumer predicate for a structural row
// from the common backend inventory. The trusted callback MUST first read that
// inventory fresh in the supplied typed identity, RequireComplete, and visit
// EVERY row in EVERY registered table/family. This predicate is no collector,
// coverage proof, persisted grant or permission to mutate a rule.
func CheckScopedDNSInactiveRule(family int, table string, tokens []string) error {
	if (family != 4 && family != 6) || table == "" || len(table) > 256 || len(tokens) < 2 || len(tokens) > 256 {
		return ErrScopedDNSRuntimeInactive
	}
	for index, token := range tokens {
		if len(token) > 4096 || strings.ContainsAny(token, "\x00\r\n") {
			return ErrScopedDNSRuntimeInactive
		}
		if index > 0 && tokens[index-1] == "--comment" {
			continue
		} // Quoted literal is inert.
		if strings.Contains(token, "RZD_") {
			return ErrScopedDNSRuntimeInactive
		}
	}
	return nil
}
