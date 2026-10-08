package dataplane

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Installed by the concrete active assembly before its actual Prepared
// callback. No decoded command/observation or detached context can supply the
// original operation cleanup review or the original provider control owner.
type nfqwsExecutionTransferGuards struct {
	committed, cleanup NFQWSActiveGuard
	originalCleanup    *operationgate.ExclusiveCleanupReview
	control            *operationgate.ControlEpochReview
}

type nfqwsExecutionTransferGuardsKey struct{}

// Pure original issuer lookup for the native tool's final Start leaf. It
// performs no forward/source/provider/tool callback. The control primitive
// separately joins and checks this actual still-held cleanup operation.
func (r *NFQWSExecutionResource) commandCleanupReview(ctx context.Context) (*operationgate.ExclusiveCleanupReview, error) {
	if r == nil || r.scope == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrNFQWSScopedOwner
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	if _, err := r.matching(r.binding); err != nil {
		return nil, err
	}
	if r.transferGuards == nil || r.transferGuards.originalCleanup == nil || r.transferGuards.control == nil {
		return nil, ErrNFQWSScopedOwner
	}
	if err := r.scope.checkOriginalOwner(ctx, &executionTransitResource{relative: r.relative, anchor: r.anchor}, false, true); err != nil {
		return nil, err
	}
	return r.transferGuards.originalCleanup, nil
}

// Exists only while this SAME Apply has completed its desired-state callback
// and fresh postimage guard. It never appears in a request or a journal.
type nfqwsExecutionTransferBarrier struct {
	self  *nfqwsExecutionTransferBarrier
	scope *executionResourceScope
	open  bool
}

func (r *NFQWSExecutionResource) bindPrepared(ctx context.Context, prepared *NFQWSPreparedHandle, observed NFQWSActiveObservation) error {
	if r == nil || r.scope == nil || r.activeCommand == nil || prepared == nil || prepared.owner == nil || ctx == nil {
		return ErrNFQWSScopedOwner
	}
	guards, ok := ctx.Value(nfqwsExecutionTransferGuardsKey{}).(nfqwsExecutionTransferGuards)
	if !ok || guards.committed == nil || guards.cleanup == nil || guards.originalCleanup == nil || guards.control == nil ||
		!guards.control.MatchesControlRoot(r.activeCommand.ControlRoot) {
		return ErrNFQWSScopedOwner
	}
	epoch := guards.control.Reference()
	if epoch.InstallationID != r.activeCommand.InstallationID || epoch.Sequence != r.activeCommand.Sequence {
		return ErrNFQWSScopedOwner
	}
	if err := guards.control.Current(ctx); err != nil {
		return err
	}
	if err := guards.originalCleanup.WithCurrent(ctx, func() error { return nil }); err != nil {
		return err
	}
	if err := prepared.VerifyOwnerObservation(ctx, observed); err != nil {
		return err
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	i, err := r.matching(r.binding)
	if err != nil || r.preparedOwner != nil || r.transferGuards != nil ||
		(r.scope.execution.Resources[i].Phase != "process-pending" && r.scope.execution.Resources[i].Phase != "capture-ready") {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := validateExecutionNFQWSObservation(*r.scope.execution, r.scope.execution.Resources[i], r.plan, observed); err != nil {
		return err
	}
	if err := r.check(ctx, true); err != nil {
		return err
	}
	nfqws2ActiveAdapterMu.Lock()
	prepared.owner.mu.Lock()
	valid := prepared.owner.adapter == r.scope.adapterOwner && prepared.owner.adapter.activeProcess == prepared.owner &&
		prepared.owner.prepared == prepared && !prepared.owner.detached && !prepared.owner.stopRequested &&
		(prepared.owner.state == "starting" || prepared.owner.state == "prepared") && prepared.owner.admission.Binding == r.binding &&
		reflect.DeepEqual(prepared.owner.command, *r.activeCommand)
	prepared.owner.mu.Unlock()
	nfqws2ActiveAdapterMu.Unlock()
	if !valid {
		return ErrNFQWSScopedOwner
	}
	r.preparedOwner, r.transferGuards = prepared, &guards
	return nil
}

// Called with the scope metadata mutex held. Actual receipt/process/queue
// observations remain the concrete assembly's separate cleanup readbacks.
func (r *NFQWSExecutionResource) checkOriginalCleanup(ctx context.Context) error {
	if r == nil || r.scope == nil || r.transferGuards == nil || r.preparedOwner == nil || ctx == nil {
		return ErrNFQWSScopedOwner
	}
	g := r.transferGuards
	return g.originalCleanup.WithCurrent(ctx, func() error {
		owner := &executionTransitResource{relative: r.relative, anchor: r.anchor}
		check := func() error {
			if err := r.scope.checkOriginalOwner(ctx, owner, false, true); err != nil {
				return err
			}
			if err := g.control.CurrentForCleanup(ctx); err != nil {
				return err
			}
			if r.scope.networkIdentity == nil {
				return ErrNetworkPolicyIdentity
			}
			return r.scope.networkIdentity.check(ctx)
		}
		if err := check(); err != nil {
			return err
		}
		nfqws2ActiveAdapterMu.Lock()
		o := r.preparedOwner.owner
		valid := o != nil && o.adapter == r.scope.adapterOwner && o.adapter.activeProcess == o
		nfqws2ActiveAdapterMu.Unlock()
		if !valid {
			return ErrNFQWSScopedOwner
		}
		return check()
	})
}

func (r *NFQWSExecutionResource) transferCurrent(ctx context.Context, binding NFQWSExecutionBinding) (int, error) {
	i, err := r.matching(binding)
	b := r.scope.nfqwsTransfer
	if err != nil || b == nil || b.self != b || b.scope != r.scope || !b.open || r.preparedOwner == nil || r.transferGuards == nil || !r.transferUsed {
		return -1, errors.Join(ErrNFQWSScopedOwner, err)
	}
	return i, r.check(ctx, true)
}

// The real producer invokes this through its one-use CommitPrepared protocol.
// The close barrier spans the helper handshake; control admission still wraps
// only actual individual effects. No callback result alone grants final ACK.
func (r *NFQWSExecutionResource) WithTransfer(ctx context.Context, binding NFQWSExecutionBinding, finish func() error) error {
	if r == nil || r.scope == nil || ctx == nil || finish == nil {
		return ErrNFQWSScopedOwner
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !time.Now().Before(deadline) || deadline.After(time.Now().Add(15*time.Second)) {
		return ErrNFQWSScopedOwner
	}
	r.scope.startMu.RLock()
	defer r.scope.startMu.RUnlock()
	if err := func() error {
		r.scope.mu.Lock()
		defer r.scope.mu.Unlock()
		i, err := r.transferCurrent(ctx, binding)
		if err != nil || r.transferEntered || r.scope.execution.Resources[i].Phase != "transfer-intent" {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		r.preparedOwner.owner.mu.Lock()
		o := r.preparedOwner.owner
		valid := o.prepared == r.preparedOwner && o.state == "committing" && !o.detached && !o.stopRequested
		o.mu.Unlock()
		if !valid {
			return ErrNFQWSScopedOwner
		}
		r.transferEntered = true
		return nil
	}(); err != nil {
		return err
	}
	if err := finish(); err != nil {
		return err
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	i, err := r.transferCurrent(ctx, binding)
	if err != nil || !r.transferACK || r.scope.execution.Resources[i].Phase != "transfer-ack" {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return nil
}

// Actual provisional lease observation and the ORIGINAL prepared handle are
// authenticated before BOTH existing records receive transfer-ack. This is
// still nonterminal intent; final ACK is a separately sealed private handle.
func (r *NFQWSExecutionResource) PublishTransferACK(ctx context.Context, observed NFQWSActiveObservation) error {
	if r == nil || r.scope == nil || r.preparedOwner == nil || ctx == nil || r.activeReadback == nil {
		return ErrNFQWSScopedOwner
	}
	if err := r.preparedOwner.VerifyOwnerObservation(ctx, observed); err != nil {
		return err
	}
	lease, err := r.preparedOwner.owner.observe(ctx, true)
	if err != nil || lease.Transfer != "provisional" || lease.observation() != observed {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := r.activeReadback(ctx, r.plan, r.root, nfqwsExecutionActiveBeforeTransfer, observed); err != nil {
		return err
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	i, err := r.transferCurrent(ctx, observed.Binding)
	if err != nil || !r.transferEntered || r.transferACK || r.scope.execution.Resources[i].Phase != "transfer-intent" {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := validateExecutionNFQWSObservation(*r.scope.execution, r.scope.execution.Resources[i], r.plan, observed); err != nil {
		return err
	}
	r.transferACK = true
	r.scope.execution.Resources[i].Phase = "transfer-ack"
	r.scope.execution.Resources[i].NFQWS.Observation = &observed
	return r.scope.persist()
}

// Final ACK is independently authenticated through the original producer.
// Retaining this handle permits exact failure compensation; it does not yet
// change the typed journal into terminal ACTIVE or release any original owner.
func (r *NFQWSExecutionResource) bindActive(ctx context.Context, handle *NFQWSActiveHandle, observed NFQWSActiveObservation) error {
	if r == nil || r.scope == nil || r.preparedOwner == nil || ctx == nil || handle == nil || handle.owner != r.preparedOwner.owner {
		return ErrNFQWSScopedOwner
	}
	if err := handle.VerifyOwnerObservation(ctx, observed); err != nil {
		return err
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	i, err := r.transferCurrent(ctx, observed.Binding)
	if err != nil || !r.transferACK || r.scope.execution.Resources[i].Phase != "transfer-ack" ||
		r.finalOwner != nil && r.finalOwner != handle {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	nfqws2ActiveAdapterMu.Lock()
	handle.owner.mu.Lock()
	valid := handle.owner.adapter == r.scope.adapterOwner && handle.owner.adapter.activeProcess == handle.owner &&
		handle.owner.active == handle && handle.owner.finalACK && !handle.owner.stopRequested
	handle.owner.mu.Unlock()
	nfqws2ActiveAdapterMu.Unlock()
	if !valid {
		return ErrNFQWSScopedOwner
	}
	r.finalOwner = handle
	return nil
}

func (s *executionResourceScope) beginNFQWSTransfer(ctx context.Context) error {
	for _, record := range s.execution.Resources {
		r := s.nfqws[record.ID]
		if r == nil || r.activeCommand == nil || record.State != "prepared" {
			continue
		}
		if r.preparedOwner == nil || r.transferGuards == nil {
			return ErrNFQWSScopedOwner
		}
		if err := r.BeginTransfer(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Manager.Apply alone calls this after its successful Store callback and fresh
// guard, while the original transaction/App borrow is held. Until publication
// of persistent ACTIVE is wired, final-owner success remains nonterminal and
// the existing journal correctly requires known compensation.
func (s *executionResourceScope) commitNFQWSTransfer(ctx context.Context) error {
	b := &nfqwsExecutionTransferBarrier{scope: s, open: true}
	b.self = b
	s.mu.Lock()
	if s.nfqwsTransfer != nil || !s.open || s.failure != nil {
		s.mu.Unlock()
		return ErrNFQWSScopedOwner
	}
	s.nfqwsTransfer = b
	s.mu.Unlock()
	defer func() { s.mu.Lock(); b.open = false; s.mu.Unlock() }()
	for _, record := range s.execution.Resources {
		r := s.nfqws[record.ID]
		if r == nil || r.activeCommand == nil || record.State != "prepared" {
			continue
		}
		if r.preparedOwner == nil || r.transferGuards == nil || record.Phase != "transfer-intent" {
			return ErrNFQWSScopedOwner
		}
		handle, err := r.preparedOwner.CommitPrepared(ctx, r.transferGuards.committed, r.transferGuards.cleanup)
		// Retain a returned original handle even when its closing bookend fails,
		// so rollback joins that same final owner rather than looking up a PID.
		s.mu.Lock()
		if handle != nil {
			r.finalOwner = handle
		}
		s.mu.Unlock()
		if err != nil || handle == nil {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		observed, err := handle.Current(ctx)
		if err != nil {
			return err
		}
		if err := handle.VerifyOwnerObservation(ctx, observed); err != nil {
			return err
		}
		if err := r.Current(ctx, observed.Binding); err != nil {
			return err
		}
	}
	return nil
}
