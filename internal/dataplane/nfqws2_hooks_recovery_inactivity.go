package dataplane

import "context"

// VerifyNFQWS2Inactive uses only the original retained startup association and
// performs fresh complete process, queue and kernel observation.
func (r *RuntimeInactivitySourceReview) VerifyNFQWS2Inactive(ctx context.Context) error {
	if err := r.CheckCurrent(ctx); err != nil {
		return err
	}
	if err := r.nfq.VerifyRuntimeInactive(ctx); err != nil {
		return err
	}
	return r.CheckCurrent(ctx)
}
