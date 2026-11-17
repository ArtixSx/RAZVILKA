package dataplane

import "context"

// Comparison only. The caller independently proves the complete restored
// standby and global listener absence after capturing this exact witness.
// No saved pointer, terminal row or joined channel can replace those reads.
func (r *domainTCPFailureCleanup) restorationListenerCurrent(ctx context.Context, w *domainTCPPoolListenerWitness) error {
	if r == nil || r.local(ctx, r.resource) != nil || r.restored || !r.imageACK || r.imageStage != "standby" || r.standby == nil || r.standby.self != r.standby || r.retained == nil || r.retained.self != r.retained || r.retained.standby != r.standby {
		return ErrPolicyAdditionUnknown
	}
	p := r.resource
	if p.records == nil || !p.records.standbyAlias.Load() || r.cursor.records != p.records || r.retained.records != p.records || r.retained.scope != p.scope || r.standby.process != p || r.standby.original == nil || r.standby.original.process != p || w == nil || w.self != w || r.cursor.listener.Load() != w || w.cursor != r.cursor || w.resource != p || w.process != p.child || w.process == nil || w.birth != p.birth || w.birth == nil || !w.frozenBirth.same(*w.birth) || w.control != p.material.control || p.executable == nil || w.executable != p.executable.file || w.config != p.config || w.endpoint != p.definition.PrivateEndpoint || w.inode == 0 || p.descriptorsClosed.Load() {
		return ErrPolicyAdditionUnknown
	}
	// Nonblocking even under the final metadata lock: the actual sole Wait
	// must already have completed. Joined additionally checks its command and
	// ProcessState, so merely closing a channel does not authorize revocation.
	select {
	case <-p.child.done:
	default:
		return ErrPolicyAdditionUnknown
	}
	return p.child.Joined(ctx)
}

// Called only at the final restoration commit under scope.mu. A foreign
// replacement or lost CAS keeps pending/failedCustody and cannot be erased.
func (r *domainTCPFailureCleanup) revokeRestorationListener(ctx context.Context, w *domainTCPPoolListenerWitness) error {
	if err := r.restorationListenerCurrent(ctx, w); err != nil {
		return err
	}
	if !r.cursor.listener.CompareAndSwap(w, nil) {
		return ErrPolicyAdditionUnknown
	}
	return nil
}
