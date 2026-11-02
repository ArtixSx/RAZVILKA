package dataplane

import (
	"context"
	"slices"
)

// OriginalMihomoLiveCommand is comparison only, never Start admission. It
// rejects interface-embedding wrappers as well as copied or escaped tokens.
// The final WithStart must still consume the original command and check its
// actual control epoch at the native Cmd.Start boundary.
func OriginalMihomoLiveCommand(ctx context.Context, admission MihomoLiveCommandAdmission, name string, args []string, review string) bool {
	c, ok := admission.(*mihomoLiveCommand)
	if !ok || c == nil || ctx == nil || ctx.Value(mihomoLiveCommandKey{}) != c {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.owner
	return c.self == c && c.open && !c.used && ctx.Err() == nil && r != nil && r.self == r &&
		r.scope != nil && r.scope.mihomoLive == r && r.scope.adapter == "mihomo" && r.scope.adapterOwner == r.adapter &&
		r.adapter != nil && r.control != nil && r.adapter.RegisteredWith(r.scope.manager) &&
		name == c.name && slices.Equal(args, c.args) && review == c.review && validPlanDigest(review)
}
