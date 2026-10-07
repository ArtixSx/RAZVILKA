//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"path/filepath"
)

// Compiled current Entware 4.4.0-11 profile. Presence of any names database is
// a capability refusal, not a request to delete/rewrite it. The retained review
// checks these negative paths before/after every read and before actual effects.
func (r *heldReview) captureStockNameAbsence(ctx context.Context, root string) error {
	canonical, err := r.resolve(root)
	if err != nil || !r.nodes[canonical].info.IsDir() {
		return at("STOCK_NAME_ROOT", err)
	}
	for _, name := range []string{"group", "rt_dsfield", "rt_protos", "rt_realms", "rt_scopes", "rt_tables", "rt_tables.d", "rt_protos.d"} {
		if ctx.Err() != nil {
			return at("STOCK_NAME_CONTEXT", ctx.Err())
		}
		if err := r.missing(filepath.Join(root, name)); err != nil {
			return at("STOCK_NAME_INPUT", err)
		}
	}
	return ctx.Err()
}
