package dataplane

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// A finite read-only operation from SAME real terminal handle. It does not
// revive the closed Apply scope, source, command admission or cleanup borrow.
type nfqwsRetiredInventoryOperation struct {
	self        *nfqwsRetiredInventoryOperation
	checks      *NetworkPolicyChecks
	execution   *nfqws2ActiveExecution
	handle      *NFQWSActiveHandle
	observation NFQWSActiveObservation
	deadline    time.Time
	open        atomic.Bool
}

type nfqwsRetiredInventoryKey struct{}

func checkNFQWSRetiredInventoryContext(ctx context.Context, c *NetworkPolicyChecks, e *nfqws2ActiveExecution) error {
	if ctx == nil {
		return ErrNFQWSScopedOwner
	}
	o, _ := ctx.Value(nfqwsRetiredInventoryKey{}).(*nfqwsRetiredInventoryOperation)
	if nfqwsRetiredInventoryPureCurrent(ctx, e) != nil || o.checks != c {
		return ErrNFQWSScopedOwner
	}
	return o.handle.VerifyRetiredObservation(ctx, o.observation)
}

func nfqwsRetiredInventoryPureCurrent(ctx context.Context, e *nfqws2ActiveExecution) error {
	if ctx == nil {
		return ErrNFQWSScopedOwner
	}
	o, _ := ctx.Value(nfqwsRetiredInventoryKey{}).(*nfqwsRetiredInventoryOperation)
	if o == nil || o.self != o || !o.open.Load() || o.execution != e || o.handle == nil || o.handle.owner == nil || o.handle.owner.admission.execution != e || ctx.Err() != nil {
		return ErrNFQWSScopedOwner
	}
	d, finite := ctx.Deadline()
	if !finite || d.After(o.deadline) || !time.Now().Before(d) {
		return ErrNFQWSScopedOwner
	}
	return nil
}

// CheckRetiredManagedNFQWSAbsence performs a fresh complete inventory/consumer/
// RPDB observation from the original successfully retired participant. A saved
// queue number, cold journal or copied handle cannot supply that provenance.
func (m *Manager) CheckRetiredManagedNFQWSAbsence(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview, h *NFQWSActiveHandle, observed NFQWSActiveObservation, checks *NetworkPolicyChecks) error {
	if m == nil || ctx == nil || cleanup == nil || checks == nil || checks.manager != m || h == nil || h.owner == nil || h.VerifyRetiredObservation(ctx, observed) != nil {
		return ErrNFQWSScopedOwner
	}
	d, finite := ctx.Deadline()
	if !finite || !time.Now().Before(d) {
		return ErrNFQWSScopedOwner
	}
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	e := h.owner.admission.execution
	if e == nil || e.self != e || e.material == nil || e.material.self != e.material || e.material.manager != m || e.material.control == nil || e.resource == nil || e.resource.scope == nil || e.resource.finalOwner != h ||
		e.material.adapter != h.owner.adapter || h.owner.admission.Provider != e.material.provider || !reflect.DeepEqual(h.owner.command, e.material.command) || !reflect.DeepEqual(h.owner.admission.Spec, e.spec) || h.owner.admission.Binding != e.resource.binding ||
		e.gate != checks.gate || e.identity != checks.identity || e.plan.LAN == nil || e.plan.LAN.Mode != LANPolicyNFQWSDirectMode {
		return ErrNFQWSScopedOwner
	}
	if m.retainedNFQOwner() != nil {
		return ErrNFQWSScopedOwner
	}
	s := e.resource.scope
	terminal := func() error {
		e.mu.Lock()
		retired := e.retired
		e.mu.Unlock()
		s.mu.Lock()
		original := retired && !s.open && !s.observationOpen.Load() && s.closedErr == nil && s.failure == nil && s.manager == m && s.adapterOwner == e.material.adapter && s.networkIdentity == e.identity &&
			s.retained && s.retainedOwner != nil && s.retainedOwner.self == s.retainedOwner && s.retainedOwner.execution == e && s.retainedOwner.scope == s && s.nfqws[e.resource.binding.ResourceID] == e.resource
		if original {
			original = nfqwsRemovedResourceDefinition(e.resource)
		}
		s.mu.Unlock()
		if !original {
			return ErrNFQWSScopedOwner
		}
		return h.VerifyRetiredObservation(ctx, observed)
	}
	return cleanup.WithCurrent(ctx, func() error {
		if err := e.material.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
			return err
		}
		if err := terminal(); err != nil {
			return err
		}
		o := &nfqwsRetiredInventoryOperation{checks: checks, execution: e, handle: h, observation: observed, deadline: d}
		o.self = o
		o.open.Store(true)
		defer o.open.Store(false)
		c := context.WithValue(ctx, nfqwsRetiredInventoryKey{}, o)
		c = context.WithValue(c, nfqws2ActiveExecutionKey{}, e)
		if err := e.owners(c); err != nil {
			return err
		}
		if err := checks.InventoryCheck(c, e.identity.value, nil); err != nil {
			return err
		}
		if err := checks.RetireCheck(c, e.plan.LAN); err != nil {
			return err
		}
		if err := e.runtimeFrozen.inspectDirectRPDB(c); err != nil {
			return err
		}
		return errors.Join(terminal(), e.owners(c), e.material.control.CurrentForCleanupOperation(c, cleanup))
	})
}

// This exact participant replaces only the old permanently closed process-only
// observer inside SAME Manager checks. Every other adapter and all standalone
// NFQ observers remain unchanged. Terminal metadata is never sufficient alone.
func (c *NetworkPolicyChecks) retiredNFQConsumer(ctx context.Context, a *NFQWS2Adapter, e *nfqws2ActiveExecution) error {
	stock, err := c.stockQueueExecution(ctx)
	if err != nil || stock == nil || stock.execution != e || e.material.adapter != a {
		return errors.Join(ErrNetworkPolicyConsumers, err)
	}
	e.mu.Lock()
	retired, invoked, prepared, failure := e.retired, e.launchInvoked, e.prepared, e.preparationErr
	e.mu.Unlock()
	if !retired || errors.Is(failure, ErrExecutionJournal) {
		return ErrNetworkPolicyConsumers
	}
	r := e.resource
	if r != nil {
		if r.scope == nil {
			return ErrNFQWSScopedOwner
		}
		r.scope.mu.Lock()
		removed := nfqwsRemovedResourceDefinition(r)
		r.scope.mu.Unlock()
		if !removed {
			return ErrNFQWSScopedOwner
		}
	}
	var receipt networkPolicyReceiptObservation
	defer receipt.close()
	if invoked {
		if r == nil || e.binding == nil {
			return ErrNFQWSScopedOwner
		}
		if r.finalOwner != nil {
			if r.finalOwner.owner == nil || r.finalOwner.owner.result == nil {
				return ErrNFQWSScopedOwner
			}
			settled, err := r.finalOwner.owner.result()
			if err != nil || r.finalOwner.VerifyRetiredObservation(ctx, settled.observation()) != nil {
				return errors.Join(ErrNFQWSScopedOwner, err)
			}
		} else {
			// A failed pre-transfer Start can retire only its SAME original
			// prepared process, with actual Wait/parent ACK already settled.
			if prepared == nil || prepared.owner == nil || !nfqws2ActiveDone(prepared.owner.done) || prepared.owner.result == nil {
				return ErrNFQWSScopedOwner
			}
			settled, err := prepared.owner.result()
			if err != nil || !prepared.owner.known(settled) || !nfqws2ActiveProcessSettled(settled) {
				return errors.Join(ErrNFQWSScopedOwner, err)
			}
		}
		receipt, err = observeNetworkPolicyEffects(ctx, r.plan.mixed, r.root, e.binding.options)
		if err != nil || !receipt.status.Removed || receipt.status.Unknown || receipt.status.Promoted {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
	} else if prepared != nil {
		return ErrNFQWSScopedOwner
	}
	if err := e.checkOriginalQueueAbsent(ctx); err != nil {
		return err
	}
	if invoked {
		if err := receipt.current(); err != nil {
			return err
		}
	}
	return stock.current(ctx)
}

// Called with the original scope mutex held. The live matching method rejects
// removed resources deliberately; terminal comparison never restores it.
func nfqwsRemovedResourceDefinition(r *NFQWSExecutionResource) bool {
	if r == nil || r.scope == nil || r.plan == nil || r.scope.execution == nil || r.scope.nfqws[r.binding.ResourceID] != r {
		return false
	}
	count := 0
	for _, recorded := range r.scope.execution.Resources {
		if recorded.ID != r.binding.ResourceID {
			continue
		}
		count++
		if recorded.Kind != "nfqws-scoped" || recorded.State != "removed" || recorded.Phase != "removed" || recorded.NFQWS == nil || recorded.NodeTransit != nil ||
			recorded.Generation != r.binding.ResourceGeneration || recorded.EffectsDigest != r.binding.EffectsDigest ||
			!reflect.DeepEqual(recorded.NFQWS.Plan, r.scope.plan) || !reflect.DeepEqual(recorded.NFQWS.Spec, r.plan.Spec()) ||
			r.scope.networkIdentity == nil || recorded.NFQWS.NetworkIdentity == nil || *recorded.NFQWS.NetworkIdentity != r.scope.networkIdentity.value {
			return false
		}
		if r.activeCommand == nil && (recorded.NFQWS.Mode != "" || recorded.NFQWS.Observation != nil) || r.activeCommand != nil && (recorded.NFQWS.Mode != nfqws2ActiveProcessMode || nfqws2ActiveCommandMatchesSpec(*r.activeCommand, recorded.NFQWS.Spec) != nil) {
			return false
		}
	}
	return count == 1
}
