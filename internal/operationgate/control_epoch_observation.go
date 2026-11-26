package operationgate

import (
	"context"
	"time"
)

// ObserveCurrent compares the SAME retained ready epoch for read-only evidence
// views. It neither acquires an operation nor authorizes any effect. Unlike
// cleanup observation, a durable Stop successor always invalidates evidence.
func (r *ControlEpochReview) ObserveCurrent(ctx context.Context) error {
	if r == nil || r.self != r || ctx == nil {
		return ErrSelfUpdateStopChanged
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !time.Now().Before(deadline) {
		return ErrSelfUpdateStopChanged
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.check(ctx)
}
