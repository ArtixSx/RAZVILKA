package dataplane

import (
	"context"
	"errors"
)

// VerifyRollback runs only after the Manager's complete reverse restoration
// and desired-state undo. A removed journal row is necessary but cannot prove
// process, TUN, selector or forwarding absence. Those are freshly observed
// through the SAME original live owner and its cleanup admission below.
func (a *MihomoProbeAdapter) VerifyRollback(ctx context.Context, plan Plan, root string) (bool, error) {
	r, err := a.phaseResource(ctx, plan, root)
	if err != nil {
		return false, err
	}
	ctx = r.resourceContext(ctx)
	cleanup, err := r.cleanupReview(ctx)
	if err != nil {
		return false, err
	}
	if err := r.rollbackRecordCurrent(ctx); err != nil {
		return false, err
	}
	ctx = context.WithValue(ctx, mihomoLiveCleanupCommandKey{}, cleanup)
	if err := r.observeLiveInactive(ctx, cleanup); err != nil {
		return false, err
	}
	if err := errors.Join(r.rollbackRecordCurrent(ctx), ctx.Err()); err != nil {
		return false, err
	}
	return true, nil
}

func (r *mihomoLiveResource) rollbackRecordCurrent(ctx context.Context) error {
	if r == nil || r.self != r || r.records == nil || r.scope == nil || ctx == nil {
		return errMihomoLiveMaterial
	}
	if err := r.records.current(ctx, true); err != nil {
		return err
	}
	s := r.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := r.localRecord(ctx, false); err != nil {
		return err
	}
	if s.failure != nil || s.execution == nil || s.execution.State != "rolling-back" {
		return errors.Join(errMihomoLiveMaterial, s.failure)
	}
	index, err := r.recordIndex()
	if err != nil {
		return err
	}
	row := s.execution.Resources[index]
	if row.State != "removed" || row.Phase != "removed" {
		return ErrExecutionJournal
	}
	return errors.Join(validateExecutionResources(*s.execution, true), ctx.Err())
}
