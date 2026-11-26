package dataplane

import (
	"context"
	"errors"
	"time"
)

// DiscardUnused settles only this original issuer's never-started resource.
// A serialized planned/unused record, copied owner or canceled forward review
// cannot establish that fact. The original cleanup operation remains required.
func (r *XraySelectedTCPExecutionResource) DiscardUnused(ctx context.Context) error {
	return r.discardUnused(ctx, true)
}

func (r *XraySelectedTCPExecutionResource) discardUnused(ctx context.Context, closeDescriptors bool) error {
	if r == nil || r.self != r || r.scope == nil || xraySelectedTCPFinite(ctx) != nil {
		return errXraySelectedTCPRuntime
	}
	r.scope.startMu.RLock()
	defer r.scope.startMu.RUnlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.startUsed && !r.startFailed || r.startACK || r.selectorUsed || r.child != nil || r.active || r.stopped || r.descriptorsClosed {
		return errXraySelectedTCPRuntime
	}
	bound, err := r.owner.cleanupContext(ctx)
	if err != nil || r.configCurrent(bound) != nil {
		return errors.Join(errXraySelectedTCPRuntime, err)
	}
	// The version command is a real child too. Do not persist terminal unused
	// while its original sole Wait is still pending, even if runtime Start
	// never happened. A later cleanup may retry using this same owner.
	if r.versionChild != nil {
		if err := r.versionChild.Joined(bound); err != nil {
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
	}
	r.scope.mu.Lock()
	index, err := r.matching()
	if err == nil && r.scope.execution.Resources[index].Phase != "planned" && r.scope.execution.Resources[index].Phase != "process-pending" {
		err = errXraySelectedTCPRuntime
	}
	if err == nil {
		r.scope.execution.Resources[index].State = "unused"
		r.scope.execution.Resources[index].Phase = "unused"
		err = r.scope.persist()
	}
	r.scope.mu.Unlock()
	// No native Start or selector was issued. Failed persistence stays sticky;
	// closing these unused descriptors cannot claim a successful journal ACK.
	if index < 0 {
		return err
	}
	if !closeDescriptors {
		return err
	}
	return errors.Join(err, r.closeDescriptorsLocked(ctx))
}

// Scope Close invokes this outside its metadata mutex and while holding the
// separate Start barrier. Unknown/live resources keep their actual descriptors
// for original compensation; closing a scope never makes them terminal.
func (r *XraySelectedTCPExecutionResource) closeOriginalDescriptors() error {
	if r == nil || r.self != r || r.scope == nil {
		return errXraySelectedTCPRuntime
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	return r.closeDescriptorsLocked(ctx)
}

func (r *XraySelectedTCPExecutionResource) closeDescriptorsLocked(ctx context.Context) error {
	r.observationMu.Lock()
	defer r.observationMu.Unlock()
	if r.descriptorsClosed {
		return r.descriptorsErr
	}
	r.scope.mu.Lock()
	index, err := r.matching()
	if err == nil {
		record := r.scope.execution.Resources[index]
		if validateXraySelectedTCPExecutionResource(record, true) != nil || record.State != "unused" && record.State != "removed" {
			err = ErrPolicyAdditionUnknown
		}
		if record.State == "unused" && (r.startUsed && !r.startFailed || r.startACK || r.child != nil || r.selectorUsed) {
			err = ErrPolicyAdditionUnknown
		}
		if record.State == "removed" && (!r.stopped || r.child == nil) {
			err = ErrPolicyAdditionUnknown
		}
	}
	r.scope.mu.Unlock()
	if err != nil {
		return errors.Join(errXraySelectedTCPRuntime, err)
	}
	if r.child != nil {
		if err := r.child.Close(ctx); err != nil {
			return err // Actual sole Wait join is required before releasing FDs.
		}
	}
	if r.versionChild != nil {
		if err := r.versionChild.Close(ctx); err != nil {
			return err
		}
	}
	r.descriptorsClosed = true
	r.commonMu.Lock()
	r.descriptorsErr = errors.Join(r.descriptorsErr, r.common.close())
	r.commonMu.Unlock()
	if r.log != nil {
		r.descriptorsErr = errors.Join(r.descriptorsErr, r.log.Close())
	}
	if r.config != nil {
		r.descriptorsErr = errors.Join(r.descriptorsErr, r.config.Close())
	}
	if r.executable != nil {
		r.descriptorsErr = errors.Join(r.descriptorsErr, r.executable.close())
	}
	if r.root != nil {
		r.descriptorsErr = errors.Join(r.descriptorsErr, r.root.Close())
	}
	return r.descriptorsErr
}
