package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// This is only an attribution of a current listener to the SAME already
// started successor. It cannot issue Start, a flow, DNS or cleanup. A prior
// baseline's original child still must have joined its sole Wait.
type domainTCPPoolListenerWitness struct {
	self               *domainTCPPoolListenerWitness
	cursor             *domainTCPGlobalSuccessor
	resource           *XrayDomainTCPExecutionResource
	process            *xraySelectedTCPProcess
	birth              *xraySelectedTCPProcessObservation
	frozenBirth        xraySelectedTCPProcessObservation
	control            *operationgate.ControlEpochReview
	config, executable *os.File
	endpoint           netip.AddrPort
	inode              uint64
	ctx                context.Context
}

// Called with resource.mu held, only AFTER the original complete listener
// proof. Later publication may hold scope.mu too, so witness reads must never
// acquire either publisher lock or invoke its external source callbacks.
func (r *XrayDomainTCPExecutionResource) retainPoolListenerWitness(ctx context.Context) error {
	c := r.scope.domainSuccessor
	if c == nil {
		return nil
	}
	if c.original() != nil || c.scope != r.scope || c.records != r.records || !r.startUsed || !r.startACK || r.birth == nil || r.child == nil || r.material == nil || r.material.control == nil {
		return ErrXrayDomainTCPOriginal
	}
	read, closeRead, err := r.originalProcessReadAlreadyHeld(ctx)
	if err != nil {
		return err
	}
	defer closeRead()
	observed, err := r.observeDomainListener(read)
	if err != nil || !r.birth.same(observed.process) || observed.endpoint != r.definition.PrivateEndpoint || observed.inode == 0 {
		return errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	w := &domainTCPPoolListenerWitness{cursor: c, resource: r, process: r.child, birth: r.birth, frozenBirth: *r.birth, control: r.material.control, config: r.config, executable: r.executable.file, endpoint: observed.endpoint, inode: observed.inode, ctx: c.scope.ctx}
	w.self = w
	if !c.listener.CompareAndSwap(nil, w) {
		return ErrXrayDomainTCPOriginal
	}
	return nil
}

func (w *domainTCPPoolListenerWitness) original(old *XrayDomainTCPExecutionResource) error {
	return w.originalAssociation(old, nil, nil)
}

// Failed cleanup may compare immutable original association after its forward
// operation ended. It cannot revive that admission or attribute a live socket.
func (w *domainTCPPoolListenerWitness) originalAssociation(old *XrayDomainTCPExecutionResource, ctx context.Context, cleanup *domainTCPFailureCleanup) error {
	if w == nil || w.self != w || w.cursor == nil || w.cursor.listener.Load() != w || w.cursor.original() != nil || w.resource == nil || w.resource.self != w.resource || w.resource.scope != w.cursor.scope || w.resource.records != w.cursor.records || w.resource.material == nil || w.resource.material.self != w.resource.material || w.resource.material.resource != w.resource || w.resource.material.control != w.control || w.control == nil || w.resource.child != w.process || w.process == nil || w.process.self != w.process || w.resource.birth != w.birth || w.birth == nil || !w.frozenBirth.same(*w.birth) || w.resource.executable == nil || w.resource.executable.file != w.executable || w.resource.config != w.config || w.ctx == nil || !sameNetworkPolicyDependency(w.ctx, w.cursor.scope.ctx) || w.resource.definition.PrivateEndpoint != w.endpoint || w.inode == 0 || w.resource.descriptorsClosed.Load() || old == nil || old.self != old || old == w.resource || old.child == nil || old.child == w.process || old.scope == nil || old.scope.manager != w.cursor.pool.manager || old.definition.PrivateEndpoint != w.endpoint || old.definition.NetworkIdentity != w.resource.definition.NetworkIdentity {
		return ErrXrayDomainTCPOriginal
	}
	if cleanup == nil {
		if w.ctx.Err() != nil || w.cursor.admission == nil || w.cursor.admission.current(w.cursor, w.cursor.scope.ctx) != nil {
			return ErrXrayDomainTCPOriginal
		}
	} else if cleanup.cursor != w.cursor || cleanup.resource != w.resource || cleanup.local(ctx, w.resource) != nil {
		return ErrXrayDomainTCPOriginal
	} else {
		a := w.cursor.admission
		if a == nil || a.self != a || a.cursor != w.cursor || a.manager != w.cursor.scope.manager || a.digest != w.cursor.scope.plan.Digest || !sameNetworkPolicyDependency(a.request, w.cursor.request) {
			return ErrXrayDomainTCPOriginal
		}
	}
	if w.resource.definition.NetworkIdentity.Validate() != nil || w.frozenBirth.network != w.resource.definition.NetworkIdentity || old.birth == nil || old.birth.network != old.definition.NetworkIdentity || old.child.self != old.child {
		return ErrXrayDomainTCPOriginal
	}
	entries, err := w.cursor.pool.originals()
	if err != nil {
		return err
	}
	found := false
	for _, e := range entries {
		if e != nil && e.detached != nil && e.detached.self == e.detached && e.detached.owner != nil && e.detached.owner.self == e.detached.owner && e.detached.owner.process == old && e.retained != nil && e.retained.self == e.retained && e.retained.scope == old.scope && e.retained.standby == e.detached.owner && e.retained.records == old.records && old.scope.plan.NetworkProfileID == w.cursor.scope.plan.NetworkProfileID {
			found = true
		}
	}
	if !found {
		return ErrXrayDomainTCPOriginal
	}
	select {
	case <-old.child.done:
	default:
		return ErrXrayDomainTCPOriginal
	}
	return nil
}

// Only this original failed cleanup can use an expired witness to reach an
// actual GLOBAL absence read after the exact child's sole Wait. No positive
// listener attribution, forward operation or native effect accepts this path.
func (w *domainTCPPoolListenerWitness) cleanupAbsent(ctx context.Context, old *XrayDomainTCPExecutionResource) error {
	if w == nil || w.resource == nil {
		return ErrXrayDomainTCPOriginal
	}
	cleanup, err := w.resource.failureCleanup(ctx)
	if err != nil || cleanup == nil {
		return errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	check := func() error {
		if err := w.originalAssociation(old, ctx, cleanup); err != nil {
			return err
		}
		if err := w.process.Joined(ctx); err != nil {
			return err
		}
		s, m := w.resource.scope, w.resource.scope.manager
		m.registryMu.RLock()
		registered := m.registryGeneration == s.registryGeneration && sameNetworkPolicyDependency(m.Adapters[s.adapter], s.adapterOwner) && s.adapterOwner == w.resource.material.adapter
		m.registryMu.RUnlock()
		if !registered || m.executionNetworkIdentity() != s.networkIdentity {
			return ErrXrayDomainTCPOriginal
		}
		w.resource.material.mu.Lock()
		err := w.resource.material.metadataIdentityCurrentLocked()
		w.resource.material.mu.Unlock()
		return errors.Join(err, w.resource.filesCurrent(ctx), w.cursor.records.current(ctx, false), w.authoredProcessRecordForCleanup(ctx, cleanup), cleanup.control.CurrentForCleanupOperation(ctx, cleanup.cleanup), ctx.Err())
	}
	if err := check(); err != nil {
		return err
	}
	return errors.Join(old.observeDomainListenerAbsent(ctx), check())
}

func (w *domainTCPPoolListenerWitness) current(ctx context.Context, old *XrayDomainTCPExecutionResource) error {
	if err := w.original(old); err != nil {
		return err
	}
	if xraySelectedTCPFinite(ctx) != nil {
		return ErrXrayDomainTCPOriginal
	}
	readCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(w.ctx, cancel)
	defer func() { stop(); cancel() }()
	check := func() error {
		if err := w.original(old); err != nil {
			return err
		}
		s, m := w.resource.scope, w.resource.scope.manager
		m.registryMu.RLock()
		registered := m.registryGeneration == s.registryGeneration && sameNetworkPolicyDependency(m.Adapters[s.adapter], s.adapterOwner) && s.adapterOwner == w.resource.material.adapter
		m.registryMu.RUnlock()
		if !registered || m.executionNetworkIdentity() != s.networkIdentity {
			return ErrXrayDomainTCPOriginal
		}
		if err := w.resource.material.metadataCurrent(readCtx); err != nil {
			return err
		}
		w.cursor.mu.Lock()
		pending := w.cursor.pending
		w.cursor.mu.Unlock()
		// Only this active original publisher can have two different authored
		// images. Both descriptors/bytes remain independently exact.
		return errors.Join(w.cursor.records.current(readCtx, !pending), w.authoredProcessRecord(), w.control.ObserveCurrent(readCtx), readCtx.Err())
	}
	if err := check(); err != nil {
		return err
	}
	r := w.resource
	read, closeRead, readErr := r.processReadContext(r.scope.contextWith(readCtx))
	if readErr != nil {
		return readErr
	}
	defer closeRead()
	observed, err := r.observeDomainListener(read)
	if err != nil || observed.inode != w.inode || observed.endpoint != w.endpoint || !w.frozenBirth.same(observed.process) {
		return errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	return check()
}

// Both images are from the actual original sink. Allow the publisher's own
// partial phase transition, never a reopened path or another resource record.
func (w *domainTCPPoolListenerWitness) authoredProcessRecord() error {
	return w.authoredProcessRecordForCleanup(nil, nil)
}

func (w *domainTCPPoolListenerWitness) authoredProcessRecordForCleanup(ctx context.Context, cleanup *domainTCPFailureCleanup) error {
	if w == nil || w.self != w || w.cursor == nil || w.cursor.records == nil || w.resource == nil || w.resource.self != w.resource || w.resource.definition.Domain == nil {
		return ErrExecutionJournal
	}
	d, r := w.cursor.records, w.resource
	if cleanup != nil && (cleanup.cursor != w.cursor || cleanup.resource != r || cleanup.local(ctx, r) != nil) {
		return ErrExecutionJournal
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	wanted, err := json.Marshal(r.definition)
	if err != nil {
		return err
	}
	for _, image := range d.images {
		var e Execution
		if json.Unmarshal(image, &e) != nil || e.PlanID != w.cursor.scope.execution.PlanID || e.Digest != w.cursor.scope.plan.Digest {
			return ErrExecutionJournal
		}
		found := 0
		for _, row := range e.Resources {
			if row.ID == r.id {
				actual, e := json.Marshal(row.XrayDomainTCP)
				phase := row.State == "prepared" && (row.Phase == "process-pending" || row.Phase == "listener-ready")
				if cleanup != nil && row.State == "removed" && row.Phase == "removed" {
					phase = true // SAME original child already joined; still no listener attribution.
				}
				if e != nil || row.Kind != "xray-domain-tcp" || !phase || row.EffectsDigest != r.definition.ConfigSHA256 || row.Generation != r.definition.Domain.Generation || !bytes.Equal(wanted, actual) {
					return ErrExecutionJournal
				}
				found++
			}
		}
		if found != 1 {
			return ErrExecutionJournal
		}
	}
	return nil
}

// Ordinary native shutdown still proves global absence. Only a prior pool
// standby can accept the fresh exact owned listener of the current successor.
func (p *XrayDomainTCPExecutionResource) observeRetainedDomainListener(ctx context.Context) error {
	if p == nil || p.self != p || p.scope == nil || p.scope.manager == nil {
		return ErrXrayDomainTCPOriginal
	}
	m := p.scope.manager
	m.retainedXrayMu.Lock()
	pool := m.domainPool
	m.retainedXrayMu.Unlock()
	if pool == nil {
		return p.observeDomainListenerAbsent(ctx)
	}
	pool.mu.Lock()
	c := pool.successor
	pool.mu.Unlock()
	if c == nil {
		return p.observeDomainListenerAbsent(ctx)
	}
	w := c.listener.Load()
	if w == nil || w.resource == p || w.endpoint != p.definition.PrivateEndpoint {
		return p.observeDomainListenerAbsent(ctx)
	}
	if domainTCPFailureCleanupOwner(ctx, c.scope) {
		return w.cleanupAbsent(ctx, p)
	}
	if err := w.original(p); err != nil {
		return err
	}
	select {
	case <-w.process.done:
		return p.observeDomainListenerAbsent(ctx)
	default:
	}
	return w.current(ctx, p)
}
