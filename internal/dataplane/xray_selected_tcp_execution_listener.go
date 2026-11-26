package dataplane

import (
	"context"
	"errors"
	"os"
	"time"
)

// The concrete publisher alone transitions the actual started resource to
// listener-ready. Observation DTOs have no publication method.
func (r *XraySelectedTCPExecutionResource) publishOriginalListener(ctx context.Context) error {
	if r == nil || r.self != r || r.child == nil || r.birth == nil || !r.startACK || !r.versionVerified {
		return errXraySelectedTCPRuntime
	}
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var observed xraySelectedTCPListenerObservation
	for {
		read, closeRead, err := r.originalProcessReadContext(c, false)
		if err != nil {
			return err
		}
		observed, err = r.child.observeListener(read, r.scope.networkIdentity.provider, r.definition.NetworkIdentity, r.definition.Match.Listener)
		if err == nil && (!r.birth.same(observed.process) || r.configCurrent(read) != nil || r.executable.current(read) != nil) {
			err = errXraySelectedTCPRuntime
		}
		closeRead()
		if err == nil {
			break
		}
		select {
		case <-r.child.done:
			return errXraySelectedTCPRuntime
		case <-c.Done():
			return errors.Join(errXraySelectedTCPRuntime, c.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !os.SameFile(observed.process.executable, r.executable.info) || !os.SameFile(observed.process.config, r.configInfo) || r.owner.checkHeld(c, false) != nil {
		return errXraySelectedTCPRuntime
	}
	metadata := r.runtimeObservation(observed)
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	i, err := r.matching()
	if err != nil || r.scope.execution.Resources[i].Phase != "process-pending" {
		return errors.Join(errXraySelectedTCPRuntime, err)
	}
	r.scope.execution.Resources[i].XraySelectedTCP.Observation = &metadata
	r.scope.execution.Resources[i].Phase = "listener-ready"
	return r.scope.persist()
}

func (r *XraySelectedTCPExecutionResource) runtimeObservation(o xraySelectedTCPListenerObservation) XraySelectedTCPRuntimeObservation {
	return XraySelectedTCPRuntimeObservation{Schema: 1, PID: o.process.pid, ParentPID: o.process.parent, ProcessGroup: o.process.group, BootID: o.process.boot, ProcessStart: o.process.start,
		ExecutableSHA256: r.executable.sha256, ArgumentsSHA256: o.process.argumentsSHA256, ConfigSHA256: o.process.configSHA256, Listener: o.endpoint, SocketInode: o.inode, NetworkIdentity: o.process.network}
}

func (r *XraySelectedTCPExecutionResource) originalListenerCurrent(ctx context.Context, cleanup bool) error {
	r.observationMu.RLock()
	defer r.observationMu.RUnlock()
	if r.descriptorsClosed || r.child == nil || r.birth == nil || !r.startACK || !r.versionVerified {
		return errXraySelectedTCPRuntime
	}
	read, closeRead, err := r.originalProcessReadContext(ctx, cleanup)
	if err != nil {
		return err
	}
	defer closeRead()
	o, err := r.child.observeListener(read, r.scope.networkIdentity.provider, r.definition.NetworkIdentity, r.definition.Match.Listener)
	if err != nil || !r.birth.same(o.process) || r.configCurrent(read) != nil || r.executable.current(read) != nil {
		return errors.Join(errXraySelectedTCPRuntime, err)
	}
	actual := r.runtimeObservation(o)
	r.scope.mu.Lock()
	i, err := r.matching()
	if err == nil && (r.scope.execution.Resources[i].XraySelectedTCP.Observation == nil || *r.scope.execution.Resources[i].XraySelectedTCP.Observation != actual) {
		err = errXraySelectedTCPRuntime
	}
	r.scope.mu.Unlock()
	return err
}
