package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// This participant is issued from the original material, never from its Spec.
// The existing Manager supplies its sole resource and both execution records.
// It owns no separate ledger and accepts no process factory or caller argv.
type nfqws2ActiveExecution struct {
	self           *nfqws2ActiveExecution
	mu             sync.Mutex
	material       *NFQWSActiveMaterial
	selection      *NFQWSScopedSelection
	plan           Plan
	spec           NFQWSScopedSpec
	panel          context.Context
	cleanup        *operationgate.ExclusiveCleanupReview
	committedGuard NFQWSActiveGuard
	cleanupGuard   NFQWSActiveGuard
	inventory      BackendInventory
	gate           *NetworkPolicyAdapter
	lan            *LANPolicyReceiptBinding
	runtime        *LANPolicyRuntime
	runtimeFrozen  LANPolicyRuntime
	lanFrozen      LANPolicyReceiptBinding
	identity       *networkPolicyIdentity
	resource       *NFQWSExecutionResource
	binding        *NFQWSScopedBinding
	prepared       *NFQWSPreparedHandle
	started        bool
	launchInvoked  bool
	preparationErr error
	retired        bool
}

type nfqws2ActiveExecutionKey struct{}

// BindExecution consumes this original source/material once for SAME Apply.
// inventory retains its actual admitted tools; gate is the SAME registered LAN
// participant. The caller holds all original owners through known retirement.
// The returned context does not itself issue a resource or authorize Start.
// committed and cleanupGuard are trusted App owners: they verify SAME Store,
// scope/control and original sealed handle in a fresh held operation. They are
// not supplied by a request, a saved flag or a reconstructed observation.
func (r *NFQWSActiveMaterial) BindExecution(ctx, panel context.Context, expected Plan, selection *NFQWSScopedSelection, inventory *BackendInventory, gate *NetworkPolicyAdapter, committed, cleanupGuard NFQWSActiveGuard) (context.Context, error) {
	if r == nil || r.self != r || panel == nil || panel.Err() != nil || selection == nil || selection.self != selection || inventory == nil || gate == nil ||
		committed == nil || cleanupGuard == nil || ctx == nil || ctx.Value(nfqws2ActiveExecutionKey{}) != nil {
		return nil, ErrNFQWSScopedOwner
	}
	if err := r.Current(ctx); err != nil {
		return nil, err
	}
	if err := selection.Current(ctx); err != nil {
		return nil, err
	}
	selection.mu.Lock()
	originalSelection := !selection.closed && selection.source == r.source && reflect.DeepEqual(selection.reference, r.reference)
	spec := selection.spec.Clone()
	selection.mu.Unlock()
	if !originalSelection || len(spec.Matches) == 0 || nfqws2ActiveCommandMatchesSpec(r.command, spec) != nil || inventory.reader.Provider != r.provider ||
		inventory.reader.Runner == nil || inventory.reader.CheckTools == nil || gate.identity == nil || gate.identity.provider != r.provider || gate.identity.value != r.command.NetworkIdentity ||
		gate.Binding == nil || gate.Binding.Runtime == nil || gate.Binding.Runtime.Runner == nil || gate.Binding.Runtime.ScopeCheck == nil ||
		inventory.reader.IPTables != gate.Binding.Runtime.IPTables || inventory.reader.IP6Tables != gate.Binding.Runtime.IP6Tables {
		return nil, ErrNFQWSScopedOwner
	}
	if _, ok := inventory.reader.Runner.(backendInventoryBoundedRunner); !ok {
		return nil, ErrNFQWSScopedOwner
	}
	r.manager.registryMu.RLock()
	registered := r.manager.Adapters[NetworkPolicyAdapterID] == gate
	r.manager.registryMu.RUnlock()
	if !registered || gate.StateRoot != filepath.Join(r.managerRoot, NetworkPolicyAdapterID) {
		return nil, ErrNFQWSScopedOwner
	}
	if _, err := CompileNFQWSScopedPlan(expected, spec); err != nil {
		return nil, err
	}
	cleanup, err := r.control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.executionBound || !time.Now().Before(r.command.ActivationDeadline) {
		return nil, ErrNFQWSScopedOwner
	}
	if err := r.currentLocked(ctx); err != nil {
		return nil, err
	}
	e := &nfqws2ActiveExecution{material: r, selection: selection, plan: cloneExecutionResourcePlan(expected), spec: spec.Clone(), panel: panel, cleanup: cleanup, committedGuard: committed, cleanupGuard: cleanupGuard,
		inventory: *inventory, gate: gate, lan: gate.Binding, runtime: gate.Binding.Runtime, identity: gate.identity, runtimeFrozen: *gate.Binding.Runtime, lanFrozen: *gate.Binding}
	e.self = e
	e.lanFrozen.Runtime = &e.runtimeFrozen
	nfqws2ActiveAdapterMu.Lock()
	available := r.adapter.activeExecution == nil && r.adapter.activeProcess == nil
	nfqws2ActiveAdapterMu.Unlock()
	if !available {
		return nil, ErrNFQWSScopedOwner
	}
	r.executionBound = true
	return context.WithValue(ctx, nfqws2ActiveExecutionKey{}, e), nil
}

// A present invalid participant always refuses. It must never fall through to
// package config/list/init phases, including a foreign adapter or copied handle.
func nfqws2ActiveExecutionFor(ctx context.Context, a *NFQWS2Adapter, p Plan, root string) (*nfqws2ActiveExecution, bool, error) {
	if ctx == nil {
		nfqws2ActiveAdapterMu.Lock()
		associated := a != nil && (a.activeExecution != nil || a.activeProcess != nil)
		nfqws2ActiveAdapterMu.Unlock()
		if associated {
			return nil, true, ErrNFQWSScopedOwner
		}
		return nil, false, nil
	}
	value := ctx.Value(nfqws2ActiveExecutionKey{})
	if value == nil {
		nfqws2ActiveAdapterMu.Lock()
		associated := a != nil && (a.activeExecution != nil || a.activeProcess != nil)
		nfqws2ActiveAdapterMu.Unlock()
		if associated {
			return nil, true, ErrNFQWSScopedOwner
		}
		return nil, false, nil
	}
	e, ok := value.(*nfqws2ActiveExecution)
	if !ok || a == nil || e == nil || e.self != e || e.material == nil || e.material.self != e.material || e.material.adapter != a ||
		!nfqws2ActiveSamePlan(e.plan, p) || root != filepath.Join(e.material.managerRoot, "transactions", e.plan.PlanID, a.ID()) {
		return nil, true, ErrNFQWSScopedOwner
	}
	return e, true, nil
}

// Manager may update only these result fields during rollback/publication.
// Every intent field, including required evidence and typed routes, is exact.
func nfqws2ActiveSamePlan(expected, actual Plan) bool {
	actual = cloneExecutionResourcePlan(actual)
	actual.State, actual.ObservedEvidence, actual.Note, actual.EvidenceNote = expected.State, expected.ObservedEvidence, expected.Note, expected.EvidenceNote
	if len(actual.RouteEvidence) != len(expected.RouteEvidence) {
		return false
	}
	for i := range actual.RouteEvidence {
		actual.RouteEvidence[i].Observed, actual.RouteEvidence[i].Source, actual.RouteEvidence[i].Note = expected.RouteEvidence[i].Observed, expected.RouteEvidence[i].Source, expected.RouteEvidence[i].Note
	}
	return reflect.DeepEqual(expected, actual)
}

// Structural/typed owner checks also serve cleanup. They deliberately do not
// query the forward source, selected scope or ready-only control after Stop.
func (e *nfqws2ActiveExecution) owners(ctx context.Context) error {
	if e == nil || e.self != e || e.material == nil || e.material.self != e.material || nfqws2ActiveOperation(ctx) != nil ||
		e.material.manager == nil || e.material.manager.StateRoot != e.material.managerRoot || e.gate == nil || e.gate.Binding != e.lan ||
		e.lan == nil || e.runtime == nil || e.lan.Runtime != e.runtime || e.material.adapter == nil || e.material.provider == nil || e.inventory.reader.CheckTools == nil ||
		e.gate.identity != e.identity || e.identity == nil || e.identity.provider != e.material.provider ||
		e.gate.StateRoot != filepath.Join(e.material.managerRoot, NetworkPolicyAdapterID) || e.identity.value != e.material.command.NetworkIdentity ||
		e.runtime.IPTables != e.inventory.reader.IPTables || e.runtime.IP6Tables != e.inventory.reader.IP6Tables || e.material.adapter.StateRoot != e.material.command.StateRoot {
		return ErrNFQWSScopedOwner
	}
	m := e.material.manager
	m.registryMu.RLock()
	valid := m.registryGeneration == e.material.registryGeneration && m.Adapters["nfqws2"] == e.material.adapter && m.Adapters[NetworkPolicyAdapterID] == e.gate
	m.registryMu.RUnlock()
	if !valid {
		return ErrNFQWSScopedOwner
	}
	e.mu.Lock()
	retired, started := e.retired, e.started
	e.mu.Unlock()
	nfqws2ActiveAdapterMu.Lock()
	associated := e.material.adapter.activeExecution == e || (!started || retired) && e.material.adapter.activeExecution == nil && e.material.adapter.activeProcess == nil
	nfqws2ActiveAdapterMu.Unlock()
	if !associated {
		return ErrNFQWSScopedOwner
	}
	return e.material.provider.WithCurrent(ctx, func(c context.Context, identity netidentity.Identity) error {
		if identity != e.material.command.NetworkIdentity {
			return ErrNFQWSScopedOwner
		}
		return e.inventory.reader.CheckTools(c, backendInventoryScope{Network: identity, ToolReviewID: e.inventory.review})
	})
}

func (e *nfqws2ActiveExecution) forward(ctx context.Context) error {
	if err := e.owners(ctx); err != nil {
		return err
	}
	if err := e.material.Current(ctx); err != nil {
		return err
	}
	if err := e.selection.Current(ctx); err != nil {
		return err
	}
	return e.owners(ctx)
}

func (e *nfqws2ActiveExecution) cleanupCurrent(ctx context.Context) error {
	if e == nil || e.cleanup == nil || e.material == nil || e.material.control == nil {
		return ErrNFQWSScopedOwner
	}
	// A final owner uses the original trusted cleanup guard on this packet's
	// fresh held App operation. A released activation borrow is never revived.
	if e.resource != nil {
		o, err := e.owner()
		if err == nil {
			o.mu.Lock()
			h, final := o.active, o.finalACK
			o.mu.Unlock()
			if final && h != nil {
				lease, err := o.observe(ctx, false)
				if err != nil || h.VerifyCleanupObservation(ctx, lease.observation()) != nil || e.cleanupGuard == nil {
					return errors.Join(ErrNFQWSScopedOwner, err)
				}
				if err := e.cleanupGuard(ctx, h, lease.observation()); err != nil {
					return err
				}
				return e.owners(ctx)
			}
		}
	}
	return e.cleanup.WithCurrent(ctx, func() error {
		if err := e.material.control.CurrentForCleanup(ctx); err != nil {
			return err
		}
		if err := e.owners(ctx); err != nil {
			return err
		}
		return e.material.control.CurrentForCleanup(ctx)
	})
}

func (e *nfqws2ActiveExecution) current(ctx context.Context, p *NFQWSScopedPlan) error {
	if e == nil || e.resource == nil || p != e.resource.Plan() {
		return ErrNFQWSScopedOwner
	}
	if err := e.forward(ctx); err != nil {
		return err
	}
	return e.resource.Current(ctx, e.resource.Binding())
}

func (e *nfqws2ActiveExecution) owner() (*nfqws2ActiveOwner, error) {
	if e == nil || e.self != e || e.resource == nil || e.material == nil || e.material.self != e.material || e.material.adapter == nil {
		return nil, ErrNFQWSScopedOwner
	}
	nfqws2ActiveAdapterMu.Lock()
	o := e.material.adapter.activeProcess
	nfqws2ActiveAdapterMu.Unlock()
	if o == nil || o.adapter != e.material.adapter || o.admission.Binding != e.resource.Binding() || !reflect.DeepEqual(o.command, e.material.command) {
		return nil, ErrNFQWSScopedOwner
	}
	return o, nil
}

func (e *nfqws2ActiveExecution) process(ctx context.Context, p *NFQWSScopedPlan, inactive bool) (NFQWSScopedProcessProof, error) {
	if e == nil || e.resource == nil || p != e.resource.Plan() {
		return NFQWSScopedProcessProof{}, ErrNFQWSScopedOwner
	}
	o, err := e.owner()
	if err != nil {
		return NFQWSScopedProcessProof{}, err
	}
	var lease nfqws2ActiveProcessLease
	if inactive {
		lease, err = nfqws2ActiveRetirementTerminal(ctx, o)
	} else {
		lease, err = o.observe(ctx, true)
		if err == nil {
			o.mu.Lock()
			prepared, active := o.prepared, o.active
			o.mu.Unlock()
			e.mu.Lock()
			original := e.prepared
			e.mu.Unlock()
			if active != nil {
				err = active.VerifyOwnerObservation(ctx, lease.observation())
			} else if prepared != nil && prepared == original {
				err = prepared.VerifyOwnerObservation(ctx, lease.observation())
			} else {
				err = ErrNFQWSScopedOwner
			}
		}
	}
	if err != nil || nfqwsScopedProcessProof(p, lease.proof(), inactive) != nil {
		return NFQWSScopedProcessProof{}, errors.Join(ErrNFQWSScopedOwner, err)
	}
	return lease.proof(), nil
}

func (e *nfqws2ActiveExecution) verifyLAN(ctx context.Context, lan *LANPolicyRuntimePlan) error {
	if e == nil || !reflect.DeepEqual(lan, e.plan.LAN) {
		return ErrNFQWSScopedOwner
	}
	ctx = networkPolicyConsumerContext(ctx, e.plan)
	if err := e.owners(ctx); err != nil {
		return err
	}
	state, err := e.gate.readOwner()
	if err != nil || state == nil || state.PlanID != e.plan.PlanID || state.Digest != e.plan.Digest || !reflect.DeepEqual(state.LAN, lan) {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	root, err := e.gate.receiptRoot(state)
	if err != nil {
		return err
	}
	status, err := e.lanFrozen.Inspect(ctx, lan, root)
	if err != nil || !status.Complete || status.Unknown || status.Removed || status.Promoted {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := e.runtimeFrozen.Verify(ctx, lan); err != nil {
		return err
	}
	after, err := e.gate.readOwner()
	closing, closeErr := e.lanFrozen.Inspect(ctx, lan, root)
	if err != nil || closeErr != nil || !reflect.DeepEqual(state, after) || status != closing {
		return errors.Join(ErrNFQWSScopedOwner, err, closeErr)
	}
	return e.owners(ctx)
}

func (e *nfqws2ActiveExecution) additional(ctx context.Context, p *NFQWSScopedPlan) error {
	if e == nil || e.resource == nil || p != e.resource.Plan() {
		return ErrNFQWSScopedOwner
	}
	if err := e.owners(ctx); err != nil {
		return err
	}
	snapshot, err := e.inventory.Read(ctx, e.material.command.NetworkIdentity)
	if err != nil || snapshot.RequireComplete() != nil || snapshot.Scope.Network != e.material.command.NetworkIdentity {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return e.owners(ctx)
}

func (e *nfqws2ActiveExecution) prepare(ctx context.Context) error {
	if err := e.forward(ctx); err != nil {
		return preflightRefusalError{err}
	}
	e.mu.Lock()
	used := e.started || e.retired
	e.mu.Unlock()
	if used || !time.Now().Before(e.material.command.ActivationDeadline) {
		return preflightRefusalError{ErrNFQWSScopedOwner}
	}
	if _, err := os.Lstat(filepath.Join(e.material.command.StateRoot, nfqws2LeaseFile)); !errors.Is(err, os.ErrNotExist) {
		return preflightRefusalError{errors.Join(ErrNFQWSScopedOwner, err)}
	}
	return nil
}

func (e *nfqws2ActiveExecution) activate(ctx context.Context) error {
	if err := e.prepare(ctx); err != nil {
		return err
	}
	if e.committedGuard == nil || e.cleanupGuard == nil || e.cleanup == nil {
		return preflightRefusalError{ErrNFQWSScopedOwner}
	}
	guards := nfqwsExecutionTransferGuards{committed: e.committedGuard, cleanup: e.cleanupGuard, originalCleanup: e.cleanup, control: e.material.control}
	ctx = context.WithValue(ctx, nfqwsExecutionTransferGuardsKey{}, guards)
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return ErrNFQWSScopedOwner
	}
	nfqws2ActiveAdapterMu.Lock()
	if e.material.adapter.activeExecution != nil || e.material.adapter.activeProcess != nil {
		nfqws2ActiveAdapterMu.Unlock()
		e.mu.Unlock()
		return preflightRefusalError{ErrNFQWSScopedOwner}
	}
	e.material.adapter.activeExecution = e
	nfqws2ActiveAdapterMu.Unlock()
	e.started = true
	e.mu.Unlock()
	readback := nfqwsExecutionReadback(func(c context.Context, p *NFQWSScopedPlan, root string, mode nfqwsExecutionReadbackMode) error {
		if e.resource == nil || p != e.resource.Plan() || root != e.resource.Root() {
			return ErrNFQWSScopedOwner
		}
		switch mode {
		case nfqwsExecutionBeforeStart:
			return nfqwsScopedBeforeStartCurrent(c, e.binding, p, e.current)
		case nfqwsExecutionRemoved:
			return e.binding.VerifyInactive(c, p, root)
		default:
			return ErrNFQWSScopedOwner
		}
	})
	activeReadback := nfqwsExecutionActiveReadback(func(c context.Context, p *NFQWSScopedPlan, root string, mode nfqwsExecutionActiveReadbackMode, observation NFQWSActiveObservation) error {
		if e.resource == nil || p != e.resource.Plan() || root != e.resource.Root() {
			return ErrNFQWSScopedOwner
		}
		e.mu.Lock()
		original := e.prepared
		e.mu.Unlock()
		if original == nil || original.VerifyOwnerObservation(c, observation) != nil {
			return ErrNFQWSScopedOwner
		}
		switch mode {
		case nfqwsExecutionActiveBeforeCapture:
			return nfqwsScopedPreparedCurrent(c, e.binding, p, root, e.current)
		case nfqwsExecutionActiveBeforeTransfer:
			return e.health(c)
		default:
			return ErrNFQWSScopedOwner
		}
	})
	ctx = context.WithValue(ctx, nfqwsExecutionReadbackKey{}, readback)
	ctx = context.WithValue(ctx, nfqwsExecutionActiveReadbackKey{}, activeReadback)
	r, err := AcquireNFQWSExecutionResource(ctx, e.spec.Clone())
	if err != nil {
		e.mu.Lock()
		e.preparationErr = err
		e.mu.Unlock()
		return err
	}
	e.resource = r
	if err := r.configureActive(ctx, e.material.command); err != nil {
		e.mu.Lock()
		e.preparationErr = err
		e.mu.Unlock()
		return err
	}
	e.binding, err = NewTypedNFQWSScopedBinding(e.material.provider, &e.inventory, NFQWSScopedBinding{
		Runner: e.inventory.reader.Runner, Tools: PolicyEffectTools{IPTables: e.inventory.reader.IPTables, IP6Tables: e.inventory.reader.IP6Tables},
		ApplyGuard: r.ApplyGuard, CleanupGuard: r.CleanupGuard, VerifyLAN: e.verifyLAN, AdditionalReadback: e.additional,
		ProcessRunning: func(c context.Context, p *NFQWSScopedPlan) (NFQWSScopedProcessProof, error) {
			return e.process(c, p, false)
		},
		ProcessInactive: func(c context.Context, p *NFQWSScopedPlan) (NFQWSScopedProcessProof, error) {
			return e.process(c, p, true)
		}})
	if err != nil {
		e.mu.Lock()
		e.preparationErr = err
		e.mu.Unlock()
		return err
	}
	admission := nfqws2ActiveProcessAdmission{Binding: r.Binding(), Spec: r.Plan().Spec(), Provider: e.material.provider,
		BeforeStart: r.BeforeStart, WithStart: r.WithStart, Current: func(c context.Context, b NFQWSExecutionBinding) error {
			if b != r.Binding() {
				return ErrNFQWSScopedOwner
			}
			return e.current(c, r.Plan())
		}, WithTransfer: r.WithTransfer, PublishTransferACK: r.PublishTransferACK,
		Prepared: func(c context.Context, b NFQWSExecutionBinding, obs NFQWSActiveObservation) error {
			p := nfqws2ActivePreparedFromContext(c)
			if p == nil || b != r.Binding() || p.VerifyOwnerObservation(c, obs) != nil {
				return ErrNFQWSScopedOwner
			}
			e.mu.Lock()
			if e.prepared != nil {
				e.mu.Unlock()
				return ErrNFQWSScopedOwner
			}
			e.prepared = p
			e.mu.Unlock()
			if err := r.bindPrepared(c, p, obs); err != nil {
				return err
			}
			if err := r.PreparedActive(c, b, obs); err != nil {
				return err
			}
			if err := e.binding.Apply(networkPolicyConsumerContext(c, e.plan), r.Plan(), r.Root()); err != nil {
				return err
			}
			return p.VerifyOwnerObservation(c, obs)
		}}
	e.mu.Lock()
	e.launchInvoked = true // Sticky even when the producer returns nil/unknown.
	e.mu.Unlock()
	p, startErr := e.material.adapter.startPreparedNFQWSProcess(ctx, e.panel, e.material.command, nil, admission)
	e.mu.Lock()
	if e.prepared == nil {
		e.prepared = p
	}
	original := e.prepared
	e.mu.Unlock()
	if startErr != nil || p == nil || p != original {
		return errors.Join(ErrNFQWSScopedOwner, startErr)
	}
	return e.health(ctx)
}

func (e *nfqws2ActiveExecution) health(ctx context.Context) error {
	if e == nil || e.resource == nil || e.binding == nil {
		return ErrNFQWSScopedOwner
	}
	ctx = networkPolicyConsumerContext(ctx, e.plan)
	if err := e.current(ctx, e.resource.Plan()); err != nil {
		return err
	}
	status, err := e.binding.Inspect(ctx, e.resource.Plan(), e.resource.Root())
	if err != nil || !status.Complete || status.Unknown || status.Removed || status.Promoted {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := e.binding.readback(ctx, e.resource.Plan(), nfqwsScopedComplete, -1); err != nil {
		return err
	}
	after, err := e.binding.Inspect(ctx, e.resource.Plan(), e.resource.Root())
	if err != nil || status != after {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return e.current(ctx, e.resource.Plan())
}

func (e *nfqws2ActiveExecution) rollback(ctx context.Context) error {
	e.mu.Lock()
	started, invoked, retired, p := e.started, e.launchInvoked, e.retired, e.prepared
	e.mu.Unlock()
	if started && !invoked && !retired {
		return e.settleUnlaunched(ctx, e.observeUnlaunched)
	}
	if err := e.cleanupCurrent(ctx); err != nil {
		return err
	}
	if retired {
		return e.cleanupCurrent(ctx)
	}
	if !started {
		e.mu.Lock()
		e.retired = true
		e.mu.Unlock()
		return e.cleanupCurrent(ctx)
	}
	if e.resource == nil || e.binding == nil || p == nil {
		return ErrNFQWSScopedOwner
	}
	o, err := e.owner()
	if err != nil {
		return err
	}
	o.mu.Lock()
	h := o.active
	final := o.finalACK
	o.mu.Unlock()
	if final && h != nil {
		_, err = h.Stop(ctx)
	} else {
		_, err = p.Stop(ctx)
	}
	if err != nil {
		return err
	}
	common := func(c context.Context, binding NFQWSExecutionBinding, proof NFQWSScopedProcessProof) error {
		if binding != e.resource.Binding() || nfqwsScopedProcessProof(e.resource.Plan(), proof, true) != nil {
			return ErrNFQWSScopedOwner
		}
		if err := e.cleanupCurrent(c); err != nil {
			return err
		}
		if err := e.binding.Remove(c, e.resource.Plan(), e.resource.Root()); err != nil {
			return err
		}
		if err := e.binding.VerifyInactive(c, e.resource.Plan(), e.resource.Root()); err != nil {
			return err
		}
		if err := e.resource.SettleRemoved(c); err != nil {
			return err
		}
		return e.cleanupCurrent(c)
	}
	if final && h != nil {
		err = e.material.adapter.retireActiveNFQWSProcess(ctx, h, common)
	} else {
		err = e.material.adapter.retirePreparedNFQWSProcess(ctx, p, common)
	}
	if err != nil {
		return err
	}
	return e.retireAssociation(ctx)
}

func (e *nfqws2ActiveExecution) retireAssociation(ctx context.Context) error {
	nfqws2ActiveAdapterMu.Lock()
	if e.material.adapter.activeExecution != e {
		nfqws2ActiveAdapterMu.Unlock()
		return ErrNFQWSScopedOwner
	}
	e.material.adapter.activeExecution = nil
	nfqws2ActiveAdapterMu.Unlock()
	e.mu.Lock()
	e.retired = true
	e.mu.Unlock()
	return e.cleanupCurrent(ctx)
}

func (e *nfqws2ActiveExecution) verifyRollback(ctx context.Context) (bool, error) {
	if err := e.cleanupCurrent(ctx); err != nil {
		return false, err
	}
	e.mu.Lock()
	retired, invoked, prepared := e.retired, e.launchInvoked, e.prepared
	e.mu.Unlock()
	if !retired {
		return false, ErrNFQWSScopedOwner
	}
	nfqws2ActiveAdapterMu.Lock()
	associated := e.material.adapter.activeProcess != nil
	nfqws2ActiveAdapterMu.Unlock()
	if associated {
		return false, ErrNFQWSScopedOwner
	}
	if invoked {
		if prepared == nil || prepared.owner == nil || !nfqws2ActiveDone(prepared.owner.done) || prepared.owner.result == nil {
			return false, ErrNFQWSScopedOwner
		}
		settled, err := prepared.owner.result()
		if err != nil || !prepared.owner.known(settled) || !nfqws2ActiveProcessSettled(settled) {
			return false, errors.Join(ErrNFQWSScopedOwner, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(e.material.command.StateRoot, nfqws2LeaseFile)); !errors.Is(err, os.ErrNotExist) {
		return false, errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := CheckTypedNFQWSScopedQueue(ctx, e.material.provider, e.material.command.NetworkIdentity, e.material.queue, nil); err != nil {
		return false, err
	}
	plan, err := CompileNFQWSScopedPlan(e.plan, e.spec.Clone())
	if err != nil {
		return false, err
	}
	snapshot, err := e.inventory.Read(ctx, e.material.command.NetworkIdentity)
	if err != nil {
		return false, err
	}
	rules, err := nfqwsScopedInventoryRules(snapshot)
	if err != nil {
		return false, err
	}
	if _, err := plan.ruleCounts(rules, nfqwsScopedAbsent); err != nil {
		return false, err
	}
	if err := CheckTypedNFQWSScopedQueue(ctx, e.material.provider, e.material.command.NetworkIdentity, e.material.queue, nil); err != nil {
		return false, err
	}
	return true, e.cleanupCurrent(ctx)
}
