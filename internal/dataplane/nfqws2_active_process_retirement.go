package dataplane

import (
	"context"
	"errors"
	"reflect"
)

// Private DEFAULT seam: the original retained COMMON execution verifies its
// actual inactive receipt/all-table inventory and settles LAN last. Neither
// Stop, a decoded image nor this callback alone can retire a participant.
func (a *NFQWS2Adapter) retirePreparedNFQWSProcess(ctx context.Context, p *NFQWSPreparedHandle, verifyCommon func(context.Context, NFQWSExecutionBinding, NFQWSScopedProcessProof) error) (err error) {
	defer nfqws2ActivePublicError("retire prepared", &err)
	if p == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	return a.retireNFQWSProcess(ctx, p.owner, p, nil, verifyCommon)
}

func (a *NFQWS2Adapter) retireActiveNFQWSProcess(ctx context.Context, h *NFQWSActiveHandle, verifyCommon func(context.Context, NFQWSExecutionBinding, NFQWSScopedProcessProof) error) (err error) {
	defer nfqws2ActivePublicError("retire active", &err)
	if h == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	return a.retireNFQWSProcess(ctx, h.owner, nil, h, verifyCommon)
}

func nfqws2ActiveDone(done <-chan struct{}) bool {
	if done == nil {
		return false
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// Always compare the actual sole Wait/parent ACK result with the live reader.
// Matching terminal metadata without that private completion is insufficient.
func nfqws2ActiveRetirementTerminal(ctx context.Context, o *nfqws2ActiveOwner) (nfqws2ActiveProcessLease, error) {
	var zero nfqws2ActiveProcessLease
	if o == nil || nfqws2ActiveOperation(ctx) != nil || !nfqws2ActiveDone(o.done) || o.result == nil {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	settled, err := o.result()
	if err != nil || !o.known(settled) || !nfqws2ActiveProcessSettled(settled) {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	live, err := o.observe(ctx, false)
	if err != nil || !reflect.DeepEqual(settled, live) || ctx.Err() != nil {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err, ctx.Err())
	}
	return settled, nil
}

func (a *NFQWS2Adapter) retireNFQWSProcess(ctx context.Context, o *nfqws2ActiveOwner, p *NFQWSPreparedHandle, h *NFQWSActiveHandle, verifyCommon func(context.Context, NFQWSExecutionBinding, NFQWSScopedProcessProof) error) error {
	if a == nil || o == nil || o.adapter != a || verifyCommon == nil || nfqws2ActiveOperation(ctx) != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	nfqws2ActiveAdapterMu.Lock()
	o.mu.Lock()
	valid := a.activeProcess == o && a.StateRoot == o.command.StateRoot && !o.retirementStarted && o.stopRequested &&
		nfqws2ActiveBindingValid(o.admission.Binding, o.command) && nfqws2ActiveCommandMatchesSpec(o.command, o.admission.Spec) == nil &&
		o.retire != nil && nfqws2ActiveDone(o.startDone) && nfqws2ActiveDone(o.done) &&
		(o.commitDone == nil || nfqws2ActiveDone(o.commitDone)) &&
		((p != nil && h == nil && o.prepared == p && !o.detached) ||
			(h != nil && p == nil && o.active == h && o.finalACK))
	retire, binding := o.retire, o.admission.Binding
	if valid {
		o.retirementStarted = true // Failure retains the fence; never retry a lost outcome.
	}
	o.mu.Unlock()
	nfqws2ActiveAdapterMu.Unlock()
	if !valid {
		return ErrNFQWSManagedProcessUnknown
	}
	settled, err := nfqws2ActiveRetirementTerminal(ctx, o)
	if err != nil {
		return err
	}
	// No owner lock spans DEFAULT/CORE callbacks; they may independently read
	// this exact terminal proof. The callback is one-use and sealed on return.
	once := &nfqws2ActiveOnce{open: true, begin: func() error {
		before, err := nfqws2ActiveRetirementTerminal(ctx, o)
		if err != nil || !reflect.DeepEqual(before, settled) {
			return errors.Join(ErrNFQWSManagedProcessUnknown, err)
		}
		if err = verifyCommon(ctx, binding, settled.proof()); err != nil {
			return err
		}
		after, err := nfqws2ActiveRetirementTerminal(ctx, o)
		if err != nil || !reflect.DeepEqual(after, settled) {
			return errors.Join(ErrNFQWSManagedProcessUnknown, err)
		}
		return ctx.Err()
	}}
	if err = once.invoke(func(common func() error) error { return retire(ctx, settled, common) }); err != nil {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	if nfqws2ActiveOperation(ctx) != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	// File removal has already been independently closed by the platform owner.
	// The original result remains immutable after done; no cold read can replace it.
	closing, err := o.result()
	if err != nil || !reflect.DeepEqual(closing, settled) {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	o.endRequestWatch()
	nfqws2ActiveAdapterMu.Lock()
	o.mu.Lock()
	valid = a.activeProcess == o && o.adapter == a && a.StateRoot == o.command.StateRoot && o.retirementStarted && o.stopRequested &&
		((p != nil && o.prepared == p && !o.detached) || (h != nil && o.active == h && o.finalACK)) && ctx.Err() == nil
	if valid {
		cancel := o.activationCancel
		if cancel != nil {
			cancel()
		}
		o.state = "retired"
		o.retiredActive = h // Only this successful original native/common close can retain it.
		o.activation, o.activationCancel, o.prepared, o.active = nil, nil, nil, nil
		o.committed, o.cleanup, o.retire = nil, nil, nil
		o.admission.BeforeStart, o.admission.WithStart, o.admission.Current, o.admission.Prepared = nil, nil, nil, nil
		o.admission.WithTransfer, o.admission.PublishTransferACK = nil, nil
		a.activeProcess = nil // Only exact Stop + COMMON cleanup + file/queue closing proof.
	}
	o.mu.Unlock()
	nfqws2ActiveAdapterMu.Unlock()
	if !valid {
		return ErrNFQWSManagedProcessUnknown
	}
	return nil
}
