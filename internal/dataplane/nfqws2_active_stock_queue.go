package dataplane

import (
	"context"
	"errors"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/components"
)

// The actual participant retains its concrete collector and queue through
// preparation, native life and known retirement. No compiled placeholder or
// caller-supplied queue list is used before original command issuance.
func (e *nfqws2ActiveExecution) observeOriginalQueue(ctx context.Context, child *components.NFQWSRuntimeProcessIdentity) (bool, error) {
	if err := e.owners(ctx); err != nil {
		return false, err
	}
	if e.plan.LAN == nil || e.plan.LAN.Mode != LANPolicyNFQWSDirectMode || e.material.queue == 0 || e.spec.Queue != e.material.queue ||
		e.spec.NetworkIdentity == nil || *e.spec.NetworkIdentity != e.material.intent.NetworkIdentity {
		return false, ErrNFQWSScopedOwner
	}
	var proof *nfqwsScopedStockQueueProof
	var err error
	if e.binding != nil && e.resource != nil {
		if e.resource.scope == nil || e.resource.plan == nil || e.resource.scope.manager != e.material.manager || e.resource.scope.adapterOwner != e.material.adapter ||
			!reflect.DeepEqual(e.resource.plan.spec, e.spec) || e.binding.network == nil || e.binding.network.provider != e.material.provider {
			return false, ErrNFQWSScopedOwner
		}
		proof, err = e.binding.stockQueueProof(ctx, e.resource.plan)
	} else {
		proof, err = nfqwsScopedPrecompiledStockQueueProof(ctx, &e.inventory, e.material.intent.NetworkIdentity, e.material.queue)
	}
	if err != nil {
		return false, err
	}
	ready, err := nfqwsScopedTypedStockQueueObserve(ctx, proof, child)
	return ready, errors.Join(err, e.owners(ctx))
}

func (e *nfqws2ActiveExecution) checkOriginalQueueAbsent(ctx context.Context) error {
	if err := e.owners(ctx); err != nil {
		return err
	}
	if e.plan.LAN == nil || e.plan.LAN.Mode != LANPolicyNFQWSDirectMode || e.material.queue == 0 || e.spec.Queue != e.material.queue {
		return ErrNFQWSScopedOwner
	}
	// Absence cannot borrow even its original compiled own-row allowance.
	// The final equal whole image must still contain no project effects.
	proof, err := nfqwsScopedPrecompiledStockQueueProof(ctx, &e.inventory, e.material.intent.NetworkIdentity, e.material.queue)
	if err != nil {
		return err
	}
	if err := checkNetworkPolicyInventoryWithStock(proof.opening, e.material.intent.NetworkIdentity, nil, LANPolicyNFQWSDirectMode, nil, proof.stockRows); err != nil {
		return err
	}
	ready, err := nfqwsScopedTypedStockQueueObserve(ctx, proof, nil)
	if err != nil || ready {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	e.mu.Lock()
	retired := e.retired
	e.mu.Unlock()
	return (&networkPolicyStockQueueObservation{execution: e, queue: e.material.queue, retired: retired}).current(ctx)
}

// Standalone native admissions retain their original strict observer. Only the
// ordinary SAME-participant admission contains this private execution pointer.
func nfqws2ActiveAdmissionQueueObserve(ctx context.Context, a nfqws2ActiveProcessAdmission, child *components.NFQWSRuntimeProcessIdentity) (bool, error) {
	e := a.execution
	if e == nil {
		if a.Spec.NetworkIdentity == nil {
			return false, ErrNFQWSScopedOwner
		}
		if child == nil {
			return false, CheckTypedNFQWSScopedQueue(ctx, a.Provider, *a.Spec.NetworkIdentity, a.Spec.Queue, nil)
		}
		return nfqwsScopedTypedQueueReadiness(ctx, a.Provider, *a.Spec.NetworkIdentity, a.Spec.Queue, child)
	}
	if e.self != e || e.material == nil || e.resource == nil || a.Provider != e.material.provider || a.Binding != e.resource.binding || !reflect.DeepEqual(a.Spec, e.spec) {
		return false, ErrNFQWSScopedOwner
	}
	return e.observeOriginalQueue(ctx, child)
}

func nfqws2ActiveAdmissionQueueCheck(ctx context.Context, a nfqws2ActiveProcessAdmission, child *components.NFQWSRuntimeProcessIdentity) error {
	ready, err := nfqws2ActiveAdmissionQueueObserve(ctx, a, child)
	if err != nil || ready != (child != nil) {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return nil
}

// Fresh whole captures bracket the original owner checks. The absence mode
// remains strict for all project effects; foreign stock rows only avoid the
// independently proven OUTPUT queue collision classification.
func (e *nfqws2ActiveExecution) observeBackendAbsent(ctx context.Context, plan *NFQWSScopedPlan) error {
	if err := e.owners(ctx); err != nil {
		return err
	}
	check := func(s BackendInventorySnapshot) error {
		if s.Scope.Network != e.material.intent.NetworkIdentity || s.Scope.ToolReviewID != e.inventory.review || s.IPTables != e.inventory.reader.IPTables || s.IP6Tables != e.inventory.reader.IP6Tables {
			return ErrNFQWSScopedOwner
		}
		stock, err := networkPolicyStockQueueRows(s, e.material.queue, nil, nil)
		if err != nil {
			return err
		}
		if plan == nil {
			return checkNetworkPolicyInventoryWithStock(s, e.material.intent.NetworkIdentity, e.plan.LAN, LANPolicyNFQWSDirectMode, nil, stock)
		}
		if !reflect.DeepEqual(plan.spec, e.spec) || !reflect.DeepEqual(plan.lan, e.plan.LAN) {
			return ErrNFQWSScopedOwner
		}
		rules, err := nfqwsScopedInventoryRules(s)
		if err != nil {
			return err
		}
		_, err = plan.ruleCountsCompared(rules, nfqwsScopedAbsent, stock)
		return err
	}
	opening, err := e.inventory.Read(ctx, e.material.intent.NetworkIdentity)
	if err != nil {
		return err
	}
	if err := check(opening); err != nil {
		return err
	}
	if err := e.owners(ctx); err != nil {
		return err
	}
	closing, err := e.inventory.Read(ctx, e.material.intent.NetworkIdentity)
	if err != nil || !reflect.DeepEqual(opening, closing) {
		return errors.Join(ErrBackendInventoryUnknown, err)
	}
	return check(closing)
}
