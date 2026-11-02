package startuptools

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Same original held tool Lease and immutable command ABI; only the sealed
// per-invocation CORE owner supplies the final short actual Start admission.
func (r *policyRunner) RunMihomoLive(ctx context.Context, admission dataplane.MihomoLiveCommandAdmission, name string, args ...string) ([]byte, error) {
	if r == nil || r.lease == nil || admission == nil {
		return nil, at("POLICY_UNISSUED", nil)
	}
	return r.lease.runPolicy(WithCommandAdmission(ctx, admission), name, args...)
}
