package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
)

// Only the actual never-issued Remove cursor may prepare this documentary
// successor. A terminal resource or saved receipt cannot construct it.
func (r *domainTCPStandbyRetirement) preparePoolKeeper(ctx context.Context) error {
	if r == nil || r.self != r || !r.cleaned || !r.publicationDone || r.owner == nil || r.owner.process == nil || r.poolRemoved == nil {
		return ErrPolicyAdditionUnknown
	}
	p := r.owner.process
	s, c := p.scope, p.scope.domainSuccessor
	if c == nil || c.original() != nil || c.scope != s || c.records != p.records {
		return ErrPolicyAdditionUnknown
	}
	if r.keeper != nil {
		return r.keeper.original()
	}
	closed, err := r.owner.baseline.retirement.ObserveClosed(ctx)
	if err != nil || closed.PossiblyIssued {
		return errors.Join(ErrDomainPolicyTCPCaptureRetirementPending, err)
	}
	continuation, err := r.owner.baseline.retirement.ReviewRetiredContinuation(ctx)
	if err != nil {
		return err
	}
	capture := r.owner.original.captureResource
	if capture == nil {
		return ErrPolicyAdditionUnknown
	}
	if r.poolCapture == nil {
		observed, err := observeNetworkPolicyEffects(ctx, capture.effects, capture.root, policyAdditionOptions{})
		if err != nil || !observed.status.Removed || observed.status.Unknown {
			observed.close()
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
		if !os.SameFile(observed.anchor, capture.anchor) {
			observed.close()
			return ErrPolicyAdditionUnknown
		}
		r.poolCapture = &observed
	}
	s.mu.Lock()
	image, err := json.Marshal(s.execution)
	terminal := validateExecutionResources(*s.execution, true)
	s.mu.Unlock()
	if err != nil || terminal != nil {
		return errors.Join(ErrExecutionJournal, err, terminal)
	}
	k := &domainTCPGlobalKeeper{pool: c.pool, cursor: c, records: p.records, image: bytes.Clone(image), digest: sha256.Sum256(image), retirement: r, continuation: continuation}
	k.self = k
	r.keeper = k
	return r.retiredPoolCurrent(ctx)
}

// Full fresh absence/receipt/ledger comparison after the original native
// descriptors close. It grants no removal or process/publication authority.
func (r *domainTCPStandbyRetirement) retiredPoolCurrent(ctx context.Context) error {
	if r == nil || r.self != r || !r.cleaned || !r.publicationDone || r.keeper == nil || r.keeper.retirement != r || r.owner == nil || r.owner.process == nil || r.poolRemoved == nil || r.poolCapture == nil || xraySelectedTCPFinite(ctx) != nil {
		return ErrPolicyAdditionUnknown
	}
	p, b := r.owner.process, r.owner.baseline
	if p.self != p || p.scope == nil || b == nil || b.self != b || r.owner.original == nil || r.owner.original.process != p || r.owner.original.baseline != b || b.tools == nil || !b.tools.valid() || b.backend == nil || b.control == nil || p.scope.networkIdentity == nil || p.child == nil {
		return ErrPolicyAdditionUnknown
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return ErrPolicyAdditionUnknown
	}
	select {
	case <-p.child.done:
	default:
		return ErrPolicyAdditionUnknown
	}
	closed, err := b.retirement.ObserveClosed(ctx)
	if err != nil || closed.PossiblyIssued {
		return errors.Join(ErrDomainPolicyTCPCaptureRetirementPending, err)
	}
	if err := errors.Join(r.poolRemoved.current(), r.poolCapture.current(), b.control.CurrentForCleanup(ctx), p.scope.networkIdentity.check(ctx), p.observeDomainListenerAbsent(ctx)); err != nil {
		return err
	}
	if !os.SameFile(r.poolRemoved.anchor, b.anchor) {
		return ErrPolicyAdditionUnknown
	}
	view, err := b.backend.Read(ctx, b.tools.Identity)
	if err != nil {
		return err
	}
	if err := view.requireLANBackendCoverage(); err != nil || view.Scope.Network != b.tools.Identity {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	for i := range b.effects.Effects {
		n, e := syntheticBaselineExactPresence(view.Rows, b.effects, i)
		if e != nil || n != 0 {
			return errors.Join(ErrPolicyAdditionUnknown, e)
		}
	}
	capture := r.owner.original.captureResource
	if capture == nil || !os.SameFile(r.poolCapture.anchor, capture.anchor) {
		return ErrPolicyAdditionUnknown
	}
	for i := range capture.effects.Effects {
		n, e := domainTCPCapturePresence(view.Rows, capture.effects, i)
		if e != nil || n != 0 {
			return errors.Join(ErrPolicyAdditionUnknown, e)
		}
	}
	closed, err = b.retirement.ObserveClosed(ctx)
	if err != nil || closed.PossiblyIssued {
		return errors.Join(ErrDomainPolicyTCPCaptureRetirementPending, err)
	}
	return errors.Join(r.poolRemoved.current(), r.poolCapture.current(), b.control.CurrentForCleanup(ctx), p.scope.networkIdentity.check(ctx), p.observeDomainListenerAbsent(ctx), ctx.Err())
}

// Transfer the SAME actual global writer descriptor into the documentary
// pair. The former alias is closed by the accepted-FD sink; no path is opened.
func (r *domainTCPStandbyRetirement) transferPoolGlobal(ctx context.Context) error {
	if r.poolAliasTransferred {
		return r.keeper.compareFiles(ctx)
	}
	o, d := r.owner, r.owner.process.records
	if err := errors.Join(d.current(ctx, true), o.globalRecordCurrent(o.process.scope.managerRoot, *o.process.scope.execution), r.retiredPoolCurrent(ctx)); err != nil {
		return err
	}
	accepted, err := transferDomainStandbyGlobal(d, o, r.keeper.image)
	if accepted {
		r.poolAliasTransferred = true
	}
	if err != nil {
		r.closeErr = errors.Join(ErrPolicyAdditionUnknown, err)
		return r.closeErr
	}
	if !accepted {
		return ErrPolicyAdditionUnknown
	}
	return r.keeper.compareFiles(ctx)
}

// Metadata custody only; the caller separately proves fresh cleanup and full
// kernel/receipt/source absence. accepted remains true on an old-alias Close
// error: the actual global FD has already changed owner and must not be lost.
func transferDomainStandbyGlobal(d *xraySelectedTCPExecutionRecords, o *domainTCPStandbyOwner, image []byte) (bool, error) {
	if d == nil || o == nil || o.self != o || o.process == nil || o.process.records != d || !d.standbyAlias.Load() {
		return false, ErrPolicyAdditionUnknown
	}
	o.latestMu.Lock()
	file, info := o.latest, o.latestInfo
	o.latestMu.Unlock()
	if file == nil || info == nil {
		return false, ErrPolicyAdditionUnknown
	}
	accepted, err := d.captureOriginalRecord(1, file, info, image, d.root, "latest-execution.json")
	if accepted {
		o.latestMu.Lock()
		if o.latest != file {
			o.latestMu.Unlock()
			return true, errors.Join(ErrPolicyAdditionUnknown, err)
		}
		o.latest, o.latestInfo = nil, nil
		o.latestMu.Unlock()
		d.standbyAlias.Store(false)
	}
	return accepted, err
}

func (r *domainTCPStandbyRetirement) closePoolCustody(ctx context.Context, retained *retainedXrayExecution) error {
	if r.closeErr != nil {
		return r.closeErr
	}
	if err := r.preparePoolKeeper(ctx); err != nil {
		return err
	}
	if !r.poolRegistryDone {
		if err := r.retireDNSOwnerRecord(ctx); err != nil {
			return err
		}
	}
	if err := r.transferPoolGlobal(ctx); err != nil {
		return err
	}
	p, s := r.owner.process, r.owner.process.scope
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
		s.owned.Close,
	}
	for r.closeIndex < len(closers) {
		if err := r.retiredPoolCurrent(ctx); err != nil {
			return err
		}
		if err := r.keeper.compareFiles(ctx); err != nil {
			return err
		}
		if err := p.material.control.CurrentForCleanupOperation(ctx, r.cleanup); err != nil {
			return err
		}
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
	if err := errors.Join(r.retiredPoolCurrent(ctx), r.keeper.compareFiles(ctx), p.material.control.CurrentForCleanupOperation(ctx, r.cleanup)); err != nil {
		return err
	}
	if !r.poolRegistryDone {
		if err := r.retireDNSRegistry(ctx); err != nil {
			return err
		}
		r.poolRegistryDone = true
	}
	m := s.manager
	m.retainedXrayMu.Lock()
	defer m.retainedXrayMu.Unlock()
	pool := r.keeper.pool
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if m.retainedXray != retained || m.domainPool != pool || pool.successor != r.keeper.cursor || pool.keeper != nil && pool.keeper != r.keeper {
		return ErrPolicyAdditionUnknown
	}
	pool.keeper = r.keeper
	s.mu.Lock()
	s.open, s.retained, s.pending = false, false, false
	s.retainedXrayOwner = nil
	s.failure = nil
	s.observationOpen.Store(false)
	s.cancel()
	s.mu.Unlock()
	p.descriptorsClosed.Store(true)
	m.retainedXray = nil
	r.owner.original.mu.Lock()
	r.owner.original.standbyOwner = nil
	r.finished = true
	r.owner.original.mu.Unlock()
	r.keeper.ready.Store(true)
	return nil
}

// Actual receipt Close errors stay sticky in the keeper. No second observer
// is opened to turn an ambiguous close into a successful transfer.
func (r *domainTCPStandbyRetirement) closePoolReceipts() error {
	if r == nil || r.poolRemoved == nil || r.poolCapture == nil {
		return ErrPolicyAdditionUnknown
	}
	closers := []func() error{r.poolRemoved.document.Close, r.poolRemoved.lock.Close, r.poolRemoved.owner.Close, r.poolCapture.document.Close, r.poolCapture.lock.Close, r.poolCapture.owner.Close}
	for r.poolReceiptClose < len(closers) {
		if err := closers[r.poolReceiptClose](); err != nil {
			return err
		}
		r.poolReceiptClose++
	}
	return nil
}
