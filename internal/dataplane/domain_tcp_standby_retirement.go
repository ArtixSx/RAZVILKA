package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type domainTCPStandbyRetirement struct {
	self            *domainTCPStandbyRetirement
	owner           *domainTCPStandbyOwner
	cleanup         *operationgate.ExclusiveCleanupReview
	receipt         networkPolicyReceiptObservation
	open            atomic.Bool
	cleaned         bool // Only actual removed receipt AND whole-kernel absence set this.
	before          *Execution
	publicationDone bool
	globalPublished bool
	closeIndex      int
	closeErr        error
	finished        bool
	closeFault      func(int) error // Private deterministic pre-close fault seam.
	publishFault    func(int) error // Same original writer, before a publication.
}
type domainTCPStandbyRetirementKey struct{}

// RetireUnpublishedStandby compensates only a reservation that the SAME joined
// source never possibly sent. TTL and empty conntrack are not cache proofs.
// Published aliases remain retained until a separate ingress/client proof.
func (o *DomainTCPOriginalScope) RetireUnpublishedStandby(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if o == nil || o.self != o || xraySelectedTCPFinite(ctx) != nil || cleanup == nil {
		return ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	owner := o.standbyOwner
	previous := o.standbyRetirement
	previousFinished := previous != nil && previous.finished
	o.mu.Unlock()
	if previousFinished {
		return nil
	}
	if owner == nil || owner.self != owner || owner.original != o || owner.process == nil || owner.process.scope == nil || owner.process.scope.manager == nil {
		return ErrDomainPolicyTCPConsumer
	}
	m := owner.process.scope.manager
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	if previous != nil {
		if previous.self != previous || previous.owner != owner || !previous.cleaned {
			return ErrPolicyAdditionUnknown
		}
		if err := owner.process.material.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
			return err
		}
		previous.cleanup = cleanup
		if !previous.open.CompareAndSwap(false, true) {
			return ErrPolicyAdditionUnknown
		}
		defer previous.open.Store(false)
		ctx = context.WithValue(owner.process.scope.contextWith(ctx), domainTCPStandbyRetirementKey{}, previous)
		retained := m.retainedXrayOwner()
		if retained == nil || retained.standby != owner {
			return ErrPolicyAdditionUnknown
		}
		if !previous.publicationDone {
			if err := previous.verifyRemoved(ctx); err != nil {
				return err
			}
		}
		return previous.publishRemoved(ctx, retained)
	}
	if err := m.checkExecutionRecovery(); err != nil {
		return err
	}
	if err := owner.current(); err != nil {
		return err
	}
	r := &domainTCPStandbyRetirement{owner: owner, cleanup: cleanup}
	r.self = r
	r.open.Store(true)
	defer r.open.Store(false)
	ctx = context.WithValue(owner.process.scope.contextWith(ctx), domainTCPStandbyRetirementKey{}, r)
	if err := r.guard(ctx); err != nil {
		return err
	}
	var err error
	r.receipt, err = observeNetworkPolicyEffects(ctx, owner.baseline.effects, owner.baseline.root, policyAdditionOptions{})
	defer r.receipt.close()
	if err != nil || !r.receipt.status.Complete || r.receipt.status.Unknown || r.receipt.status.Removed {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	if err := r.receipt.current(); err != nil {
		return err
	}
	s := owner.process.scope
	s.mu.Lock()
	retained := s.retainedXrayOwner
	if retained == nil || retained.standby != owner || retained.pending {
		s.mu.Unlock()
		return ErrPolicyAdditionUnknown
	}
	retained.pending = true // No known read/forward result during compensation.
	s.mu.Unlock()
	o.mu.Lock()
	o.standbyRetirement = r
	o.mu.Unlock()
	plan := owner.baseline.effects
	runtime := PolicyEffectRuntime{Runner: r, Tools: PolicyEffectTools{IPTables: owner.baseline.tools.IPTables}, Preflight: r.guard, Guard: func(c context.Context, _ int) error { return r.guard(c) },
		ExactPresence: func(c context.Context, i int) (int, error) {
			view, err := r.read(c)
			if err != nil {
				return 0, err
			}
			return syntheticBaselineExactPresence(view.Rows, plan, i)
		},
		BeforeDelete: func(c context.Context, i int) error {
			view, err := r.read(c)
			if err != nil {
				return err
			}
			return syntheticBaselineDeletionReady(view.Rows, plan, i)
		}}
	if err := RemovePolicyEffectsWithReceipt(ctx, runtime, plan, owner.baseline.root); err != nil {
		return err
	}
	removed, err := observeNetworkPolicyEffects(ctx, plan, owner.baseline.root, policyAdditionOptions{})
	defer removed.close()
	if err != nil || !removed.status.Removed || removed.status.Unknown {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	view, err := r.read(ctx)
	if err != nil {
		return err
	}
	for i := range plan.Effects {
		count, e := syntheticBaselineExactPresence(view.Rows, plan, i)
		if e != nil || count != 0 {
			return errors.Join(ErrPolicyAdditionUnknown, e)
		}
	}
	if err := removed.current(); err != nil {
		return err
	}
	r.cleaned = true
	if err := r.guard(ctx); err != nil {
		return err
	}
	return r.publishRemoved(ctx, retained)
}

// A cached cleanup ACK never issues a fresh terminal outcome. Before retrying
// a partial publication, observe the original closed inputs and actual full
// kernel absence again; foreign reinsertions are refused, never deleted.
func (r *domainTCPStandbyRetirement) verifyRemoved(ctx context.Context) error {
	if !r.cleaned {
		return ErrPolicyAdditionUnknown
	}
	if err := r.guard(ctx); err != nil {
		return err
	}
	b := r.owner.baseline
	view, err := r.read(ctx)
	if err != nil {
		return err
	}
	for i := range b.effects.Effects {
		count, e := syntheticBaselineExactPresence(view.Rows, b.effects, i)
		if e != nil || count != 0 {
			return errors.Join(ErrPolicyAdditionUnknown, e)
		}
	}
	receipt, err := observeNetworkPolicyEffects(ctx, b.effects, b.root, policyAdditionOptions{})
	defer receipt.close()
	if err != nil || !receipt.status.Removed || receipt.status.Unknown {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	if err := receipt.current(); err != nil {
		return err
	}
	return r.guard(ctx)
}

func (r *domainTCPStandbyRetirement) guard(ctx context.Context) error {
	if r == nil || r.self != r || !r.open.Load() || ctx == nil || ctx.Value(domainTCPStandbyRetirementKey{}) != r || r.owner == nil || r.owner.self != r.owner || r.cleanup == nil || xraySelectedTCPFinite(ctx) != nil {
		return ErrDomainPolicyTCPConsumer
	}
	o := r.owner
	p := o.process
	if p == nil || p.material == nil || o.original == nil || o.original.standbyOwner != o || p.scope == nil || p.scope.manager == nil {
		return ErrDomainPolicyTCPConsumer
	}
	retained := p.scope.manager.retainedXrayOwner()
	if retained == nil || retained.standby != o {
		return ErrDomainPolicyTCPConsumer
	}
	p.scope.mu.Lock()
	err := p.scope.checkOriginalOwner(ctx, nil, false, false)
	original := p.scope.retained && p.scope.retainedXrayOwner == retained
	p.scope.mu.Unlock()
	if err != nil || !original {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	if err := p.material.control.CurrentForCleanupOperation(ctx, r.cleanup); err != nil {
		return err
	}
	if err := p.records.current(ctx, !r.cleaned); err != nil {
		return err
	}
	if err := p.filesCurrent(ctx); err != nil {
		return err
	}
	if err := o.original.captureResource.closedStandbyLocal(ctx); err != nil {
		return err
	}
	if err := o.baseline.local(ctx); err != nil {
		return err
	}
	closed, err := o.baseline.retirement.ObserveClosed(ctx)
	if err != nil || closed.PossiblyIssued {
		return errors.Join(ErrDomainPolicyTCPCaptureRetirementPending, err)
	}
	if err := p.observeDomainListenerAbsent(ctx); err != nil {
		return err
	}
	if err := p.scope.networkIdentity.check(ctx); err != nil {
		return err
	}
	return o.baseline.tools.Runner.CheckSyntheticDNS(ctx, o.baseline.tools.Identity)
}

func (r *domainTCPStandbyRetirement) read(ctx context.Context) (backendInventorySnapshot, error) {
	if err := r.guard(ctx); err != nil {
		return backendInventorySnapshot{}, err
	}
	b := r.owner.baseline
	view, err := b.backend.Read(ctx, b.tools.Identity)
	if err != nil {
		return backendInventorySnapshot{}, err
	}
	if err := view.requireLANBackendCoverage(); err != nil || view.Scope.Network != b.tools.Identity {
		return backendInventorySnapshot{}, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	return view, r.guard(ctx)
}

func (r *domainTCPStandbyRetirement) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := r.guard(ctx); err != nil {
		return nil, err
	}
	return r.owner.baseline.tools.Runner.RunSyntheticDNS(ctx, r, name, args...)
}
func (*domainTCPStandbyRetirement) syntheticDNSCommandAdmission() {}
func (r *domainTCPStandbyRetirement) WithStart(ctx context.Context, name string, args []string, review string, begin func() error) error {
	if r == nil || r.self != r || !r.open.Load() || ctx.Value(domainTCPStandbyRetirementKey{}) != r || begin == nil {
		return ErrDomainPolicyTCPConsumer
	}
	b := r.owner.baseline
	if review != b.tools.ReviewSHA256 || name != b.tools.IPTables {
		return ErrDomainPolicyTCPConsumer
	}
	invocation, err := observePolicyEffectCommandInvocation(ctx, b.effects, b.root, name, args)
	if err != nil || invocation == nil || !invocation.cleanup || !reflect.DeepEqual(args, b.effects.Effects[invocation.index].Delete) {
		return errors.Join(ErrPolicyAdditionReceipt, err)
	}
	s := r.owner.process.scope
	s.startMu.RLock()
	defer s.startMu.RUnlock()
	return invocation.withStart(ctx, func() error {
		s.mu.Lock()
		valid := r.open.Load() && s.open && s.failure == nil && s.retainedXrayOwner != nil && s.retainedXrayOwner.standby == r.owner
		s.mu.Unlock()
		if !valid {
			return ErrDomainPolicyTCPConsumer
		}
		return b.control.WithCleanupStart(ctx, r.cleanup, begin)
	})
}

func checkDomainStandbyOriginalLoadedReceipt(ctx context.Context, b *policyEffectReceiptBorrow) error {
	if ctx == nil {
		return ErrPolicyAdditionReceipt
	}
	raw := ctx.Value(domainTCPStandbyRetirementKey{})
	if raw == nil {
		return nil
	}
	r, ok := raw.(*domainTCPStandbyRetirement)
	if !ok || r == nil || r.self != r || !r.open.Load() || b == nil {
		return ErrPolicyAdditionReceipt
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	p := r.receipt
	if b.currentOwner() != nil || b.publishedInfo == nil || p.fileInfo == nil || !os.SameFile(p.fileInfo, b.publishedInfo) || !os.SameFile(p.lockInfo, b.markerInfo) || !os.SameFile(p.anchor, b.anchor) || !bytes.Equal(p.canonical, b.publishedBytes) || b.session.path != r.owner.baseline.root {
		return ErrPolicyAdditionReceipt
	}
	return nil
}

func (r *domainTCPStandbyRetirement) publishRemoved(ctx context.Context, retained *retainedXrayExecution) error {
	o, s := r.owner, r.owner.process.scope
	if !r.cleaned {
		return ErrPolicyAdditionUnknown
	}
	if r.closeErr != nil {
		return r.closeErr
	}
	if r.publicationDone {
		return r.closeOriginalCustody(ctx, retained)
	}
	s.mu.Lock()
	if r.before == nil {
		beforeRaw, err := json.Marshal(s.execution)
		var before Execution
		if err == nil {
			err = json.Unmarshal(beforeRaw, &before)
		}
		if err != nil {
			s.mu.Unlock()
			return err
		}
		r.before = &before
	}
	for i := range s.execution.Resources {
		record := &s.execution.Resources[i]
		if record.ID == filepath.Base(o.baseline.relative) {
			record.State, record.Phase = "removed", "removed"
		}
	}
	s.execution.State = "temporary-complete"
	if err := validateExecutionResources(*s.execution, true); err != nil {
		s.mu.Unlock()
		return err
	}
	data, err := json.Marshal(s.execution)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	d := o.process.records
	if err := d.beforePublication(); err != nil {
		return err
	}
	for i := range 2 {
		if r.publishFault != nil {
			if err := r.publishFault(i); err != nil {
				return err
			}
		}
		root, name := d.recordPath(i)
		file, err := root.WriteAtomicRetained(name, data, 0600)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err == nil {
			err = d.captureOriginalRecord(i, file, info, data, root, name)
		}
		if err != nil {
			return errors.Join(err, file.Close())
		}
	}
	named, err := os.Lstat(filepath.Join(s.managerRoot, "latest-execution.json"))
	if err != nil {
		return err
	}
	if os.SameFile(o.latestInfo, named) {
		if r.publishFault != nil {
			if err := r.publishFault(2); err != nil {
				return err
			}
		}
		expected := *r.before
		if r.globalPublished {
			expected = *s.execution
		}
		if err := o.globalRecordCurrent(s.managerRoot, expected); err != nil {
			return err
		}
		if !r.globalPublished {
			file, err := d.root.WriteAtomicRetained("latest-execution.json", data, 0600)
			if err != nil {
				return err
			}
			info, err := file.Stat()
			if err != nil {
				return errors.Join(err, file.Close())
			}
			old := o.latest
			o.latest, o.latestInfo = file, info
			r.globalPublished = true
			if err := old.Close(); err != nil {
				return err
			}
			if err := o.globalRecordCurrent(s.managerRoot, *s.execution); err != nil {
				return err
			}
		}
	}
	if err := d.current(ctx, true); err != nil {
		return err
	}
	r.publicationDone = true
	return r.closeOriginalCustody(ctx, retained)
}

func (r *domainTCPStandbyRetirement) closeOriginalCustody(ctx context.Context, retained *retainedXrayExecution) error {
	o, s := r.owner, r.owner.process.scope
	p := o.process
	if err := r.retireDNSOwnerRecord(ctx); err != nil {
		return err
	}
	closers := []func() error{
		func() error {
			if p.log != nil {
				return p.log.Close()
			}
			return nil
		},
		func() error {
			if p.config != nil {
				return p.config.Close()
			}
			return nil
		},
		func() error {
			if p.executable != nil {
				return p.executable.file.Close()
			}
			return nil
		},
		func() error {
			if p.root != nil {
				return p.root.Close()
			}
			return nil
		},
		p.records.close,
		o.latest.Close,
		s.owned.Close,
	}
	for r.closeIndex < len(closers) {
		if r.closeFault != nil {
			if err := r.closeFault(r.closeIndex); err != nil {
				return err
			}
		}
		if err := closers[r.closeIndex](); err != nil {
			r.closeErr = errors.Join(ErrPolicyAdditionUnknown, err)
			return r.closeErr
		}
		r.closeIndex++
	}
	m := s.manager
	m.retainedXrayMu.Lock()
	defer m.retainedXrayMu.Unlock()
	if m.retainedXray != retained {
		return ErrPolicyAdditionUnknown
	}
	if err := r.retireDNSRegistry(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	s.open = false
	s.retained = false
	s.retainedXrayOwner = nil
	s.observationOpen.Store(false)
	s.cancel()
	s.mu.Unlock()
	p.descriptorsClosed.Store(true)
	m.retainedXray = nil
	o.original.mu.Lock()
	o.original.standbyOwner = nil
	r.finished = true
	o.original.mu.Unlock()
	return nil
}

func (r *domainTCPStandbyRetirement) originalDNSMode() (*ScopedDNSAdapter, *scopedDNSSession, *scopedDNSSyntheticMode, error) {
	if r == nil || r.self != r || !r.cleaned || !r.publicationDone || r.owner == nil || r.owner.process == nil || r.owner.original == nil {
		return nil, nil, nil, ErrDomainPolicyTCPConsumer
	}
	p := r.owner.process
	m := p.material
	if m == nil || m.binding == nil || m.binding.self != m.binding || m.binding.adapter == nil || m.session == nil || m.session.synthetic == nil {
		return nil, nil, nil, ErrDomainPolicyTCPConsumer
	}
	a, s := m.binding.adapter, m.session
	mode := s.synthetic
	if mode.binding != m.binding || mode.control != m.control || mode.source != m.dnsSource || mode.ownerRecord == nil || mode.ownerRecord.self != mode.ownerRecord || mode.ownerRecord.path != a.StateRoot || m.binding.root != a.StateRoot {
		return nil, nil, nil, ErrDomainPolicyTCPConsumer
	}
	return a, s, mode, nil
}
func (r *domainTCPStandbyRetirement) retireDNSOwnerRecord(ctx context.Context) error {
	a, s, mode, err := r.originalDNSMode()
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.live != s || s.inactiveJoined() != nil {
		return ErrDomainPolicyTCPConsumer
	}
	// The finalizer already proved this exact joined final ledger never sent.
	// No public/cold record can enter this private original close cursor.
	return mode.ownerRecord.retire(ctx)
}
func (r *domainTCPStandbyRetirement) retireDNSRegistry(ctx context.Context) error {
	a, s, mode, err := r.originalDNSMode()
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.live != s || mode.ownerRecord.closeErr != nil {
		return errors.Join(ErrDomainPolicyTCPConsumer, mode.ownerRecord.closeErr)
	}
	// Keep the LAST original file/root descriptors until every other close
	// completed. Both names and canonical bytes are checked afresh on every
	// retry and immediately before these final closes and registry publication.
	if err := mode.ownerRecord.retire(ctx); err != nil {
		return err
	}
	if err := mode.ownerRecord.close(); err != nil {
		r.closeErr = errors.Join(ErrPolicyAdditionUnknown, err)
		return r.closeErr
	}
	if err := scopedDNSInactiveRetire(a.StateRoot, s); err != nil {
		return err
	}
	a.live = nil
	return nil
}
