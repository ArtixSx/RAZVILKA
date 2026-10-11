package physicalscope

import (
	"context"
	"reflect"
)

// VerifyRetainedIncarnation compares ONLY the immutable original physical scope
// through this SAME Observer, live Review, retained NI and continuity fence.
// It never reads current user selection, config, consent or Store and never
// adopts facts or opens a replacement Review. Selection-only forward revocation
// remains revoked. Physical drift/uncertainty permanently refuses both paths.
// This is a read-only fact check, NOT cleanup/effect/forward admission. The caller
// must hold its separate original cleanup capability and exact original receipts.
func (o *Observer) VerifyRetainedIncarnation(ctx context.Context, r *Review) error {
	if !o.ready() || r == nil || r.state == nil || r.state.self != r {
		return at("retained.dependencies", nil)
	}
	c, cancel, err := operationContext(ctx)
	if err != nil {
		return boundary("retained.context", err)
	}
	defer cancel()
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.issuer != o || s.closed || s.physicalInvalid || s.fence == nil {
		return at("retained.review.unavailable", nil)
	}
	selection := cloneSnapshot(s.snapshot).Selection
	snapshot, _, err := o.captureObservation(c, selection, s.snapshot.Identity, s.fence, &s.snapshot, false, s.snapshot.ReviewID)
	if err != nil || !reflect.DeepEqual(snapshot, s.snapshot) {
		s.invalid, s.physicalInvalid = true, true
		if err != nil {
			return boundary("retained.capture", err)
		}
		return boundary("retained.snapshot", at(snapshotDifference(s.snapshot, snapshot), nil))
	}
	return nil
}
