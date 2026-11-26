package startuptools

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// The original proxy compiler uses implicit IPv4 for route/rule effects. Only
// its exact original Mihomo per-call token may use this spelling. Validate the
// existing explicit-family grammar but execute the unchanged, sealed raw argv.
func mihomoLiveImplicitIPv4Effect(ctx context.Context, name, review string, index int, args []string) bool {
	if ctx == nil || index != 2 || len(args) < 3 || args[0] != "route" && args[0] != "rule" {
		return false
	}
	if !effectArguments(2, append([]string{"-4"}, args...)) {
		return false
	}
	binding, ok := ctx.Value(admissionKey{}).(commandAdmission)
	if !ok || binding.owner == nil {
		return false
	}
	original, ok := binding.owner.(dataplane.MihomoLiveCommandAdmission)
	return ok && dataplane.OriginalMihomoLiveCommand(ctx, original, name, args, review)
}
