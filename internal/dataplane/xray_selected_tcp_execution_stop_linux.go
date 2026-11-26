//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"syscall"
)

// Signal only the actual retained os.Process, whose sole Wait remains here.
// No PIDfile, ProcessController, process group or persisted observation is a
// signal target. Cancellation never releases the owner before actual joining.
func (r *XraySelectedTCPExecutionResource) stopOriginalNative(ctx context.Context) error {
	if r == nil || r.self != r || r.scope == nil || r.child == nil || !r.startACK || xraySelectedTCPFinite(ctx) != nil {
		return errXraySelectedTCPRuntime
	}
	r.observationMu.Lock()
	defer r.observationMu.Unlock()
	bound, err := r.owner.cleanupContext(ctx)
	if err != nil {
		return err
	}
	if r.child.commandCurrent() != nil || r.child.child == nil {
		return errXraySelectedTCPRuntime
	}
	select {
	case <-r.child.done:
	default:
		cleanup := r.material.cleanup
		if op, ok := bound.Value(xrayRetainedOperationKey{}).(*xrayRetainedOperation); ok && op != nil && op.self == op && op.open.Load() && op.owner != nil && op.owner.execution != nil && op.owner.execution.resource == r && !op.forward && op.cleanup != nil {
			cleanup = op.cleanup
		}
		err := r.material.control.WithCleanupStart(bound, cleanup, func() error {
			if err := r.child.child.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if err := r.child.Joined(bound); err != nil {
		return err
	}
	if err := xraySelectedTCPObserveListenerAbsent(bound, r.scope.networkIdentity.provider, r.definition.NetworkIdentity, r.definition.Match.Listener); err != nil {
		return err
	}
	return xraySelectedTCPObserveConntrackSettled(bound, r.scope.networkIdentity.provider, r.definition.NetworkIdentity, r.definition.Match)
}
