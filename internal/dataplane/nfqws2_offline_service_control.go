package dataplane

import "context"

// CheckOfflineServiceControl validates retained ownership for a manual-mode
// configuration change only. It does not observe the live process or network,
// grant Apply/Stop/recovery authority, or attest service reachability. Callers
// must retain private lifetime leases and compare original file images.
func (a *NFQWS2Adapter) CheckOfflineServiceControl(ctx context.Context, prior Plan) error {
	if a == nil || ctx == nil || ctx.Err() != nil || !NFQWS2OfflineStopPlanScope(prior) {
		return ErrReviewChanged
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrReviewChanged
	}
	transaction, ok := a.firstStartTransaction(prior)
	if !ok {
		return ErrReviewChanged
	}
	lease, err := a.readLease()
	if err != nil || lease == nil || lease.FirstStart == nil || lease.FirstStart.Phase != nfqws2FirstRunning || lease.FirstStart.Process == nil {
		return ErrReviewChanged
	}
	if lease.Transaction != transaction {
		return ErrReviewChanged
	}
	return ctx.Err()
}
