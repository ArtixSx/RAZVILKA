package dataplane

import (
	"context"
	"errors"
	"sync"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Frozen associations only. The unchanged complete NFQ observer still reads
// every process, queue, inventory, source and receipt below. In particular,
// these pointers never constitute an active-consumer allowance.
type networkPolicyNFQReadSources struct {
	checks    *NetworkPolicyChecks
	adapter   *NFQWS2Adapter
	execution *nfqws2ActiveExecution
	material  *NFQWSActiveMaterial
	resource  *NFQWSExecutionResource
	binding   *NFQWSScopedBinding
	plan      *NFQWSScopedPlan
	process   *nfqws2ActiveOwner
	identity  *networkPolicyIdentity
	inventory *BackendInventory
	provider  *netidentity.Provider
	runner    NFQWS2Runner
	review    string
}

func (c *NetworkPolicyChecks) nfqReadSources(ctx context.Context) *networkPolicyNFQReadSources {
	if c == nil || ctx == nil || c.inventory == nil || c.inventory.reader.Runner == nil || ctx.Value(nfqwsRetiredInventoryKey{}) != nil || ctx.Value(nfqwsProbeCleanupKey{}) != nil {
		return nil
	}
	e, ok := ctx.Value(nfqws2ActiveExecutionKey{}).(*nfqws2ActiveExecution)
	if !ok || e == nil || e.self != e || e.material == nil || e.material.self != e.material || e.resource == nil || e.binding == nil || e.inventory.reader.Runner == nil {
		return nil // Existing absent/model/custom/refusal path, unchanged.
	}
	a, ok := c.adapters["nfqws2"].(*NFQWS2Adapter)
	if !ok || a == nil || e.material.adapter != a {
		return nil
	}
	if _, ok := e.inventory.reader.Runner.(nfqwsProbeToolObserver); !ok {
		return nil
	}
	e.mu.Lock()
	retired := e.retired
	e.mu.Unlock()
	if retired {
		return nil
	}
	nfqws2ActiveAdapterMu.Lock()
	process, original := a.activeProcess, a.activeExecution == e
	nfqws2ActiveAdapterMu.Unlock()
	if !original {
		return nil
	}
	return &networkPolicyNFQReadSources{checks: c, adapter: a, execution: e, material: e.material, resource: e.resource, binding: e.binding, plan: e.resource.plan, process: process,
		identity: c.identity, inventory: c.inventory, provider: e.inventory.reader.Provider, runner: e.inventory.reader.Runner, review: e.inventory.review}
}

func (s *networkPolicyNFQReadSources) current(ctx context.Context) error {
	if s == nil || ctx == nil || nfqws2ActiveOperation(ctx) != nil || s.checks == nil || s.material == nil || s.resource == nil || s.binding == nil || s.inventory == nil || s.inventory.reader.Runner == nil || s.execution == nil || s.execution.self != s.execution || ctx.Value(nfqws2ActiveExecutionKey{}) != s.execution {
		return ErrNetworkPolicyConsumers
	}
	c, e := s.checks, s.execution
	if c.inventory == nil || c.inventory.reader.Runner == nil || e.inventory.reader.Runner == nil {
		return ErrNetworkPolicyConsumers
	}
	if e.material != s.material || s.material.self != s.material || s.material.adapter != s.adapter || s.material.manager != c.manager || e.resource != s.resource || e.binding != s.binding || s.resource.plan != s.plan || s.plan == nil ||
		c.adapters["nfqws2"] != s.adapter || e.gate != c.gate || e.lan != c.binding || e.runtime != c.runtime || e.identity != s.identity || c.identity != s.identity || s.identity == nil ||
		c.inventory != s.inventory || c.inventory.reader.Provider != s.provider || e.inventory.reader.Provider != s.provider || s.identity.provider != s.provider || s.material.provider != s.provider ||
		e.inventory.review != s.review || c.inventory.review != s.review || !sameNetworkPolicyDependency(e.inventory.reader.Runner, s.runner) || !sameNetworkPolicyDependency(c.inventory.reader.Runner, s.runner) ||
		c.inventory.reader.IPTables != e.inventory.reader.IPTables || c.inventory.reader.IP6Tables != e.inventory.reader.IP6Tables {
		return ErrNetworkPolicyConsumers
	}
	e.mu.Lock()
	retired := e.retired
	e.mu.Unlock()
	nfqws2ActiveAdapterMu.Lock()
	associated := s.adapter.activeExecution == e && s.adapter.activeProcess == s.process
	nfqws2ActiveAdapterMu.Unlock()
	if retired || !associated {
		return ErrNetworkPolicyConsumers
	}
	return c.current(ctx)
}

func (c *NetworkPolicyChecks) nfqConsumers(ctx context.Context, lan *LANPolicyRuntimePlan) ([]networkPolicyNFQObservation, error) {
	if c != nil && ctx != nil {
		if e, ok := ctx.Value(nfqws2ActiveExecutionKey{}).(*nfqws2ActiveExecution); ok && e != nil && (e.inventory.reader.Runner == nil || c.inventory != nil && c.inventory.reader.Runner == nil) {
			return nil, ErrNetworkPolicyConsumers
		}
	}
	s := c.nfqReadSources(ctx)
	if s == nil {
		return c.nfqConsumersObserved(ctx, lan)
	}
	if err := s.current(ctx); err != nil {
		return nil, err
	}
	return networkPolicyNFQReadOnce(ctx, s.execution,
		func(use func(context.Context) error) error { return s.binding.observeActiveTools(ctx, s.plan, use) },
		s.current, func(observed context.Context) ([]networkPolicyNFQObservation, error) {
			return c.nfqConsumersObserved(observed, lan)
		})
}

// Only the original consumer caller above supplies production callbacks. The
// views contain retained receipt FDs, never the borrowed context/tool marker.
// Closing a tool loan may fail AFTER a successful body: close those views too.
func networkPolicyNFQReadOnce(parent context.Context, execution *nfqws2ActiveExecution, observe func(func(context.Context) error) error, current func(context.Context) error, read func(context.Context) ([]networkPolicyNFQObservation, error)) ([]networkPolicyNFQObservation, error) {
	if parent == nil || observe == nil || current == nil || read == nil {
		return nil, ErrNetworkPolicyConsumers
	}
	var mu sync.Mutex
	open, entered, finished, invalid := true, false, false, false
	var published, result []networkPolicyNFQObservation
	var bodyErr error
	keep := false
	closeViews := func(views []networkPolicyNFQObservation) {
		for _, observation := range views {
			observation.close()
		}
	}
	defer func() {
		mu.Lock()
		open = false
		left := published
		published = nil
		mu.Unlock()
		closeViews(left)
		if !keep {
			closeViews(result)
		}
	}()
	outer := observe(func(child context.Context) (callbackErr error) {
		mu.Lock()
		if !open || entered {
			invalid = true
			mu.Unlock()
			return ErrNetworkPolicyConsumers
		}
		entered = true
		mu.Unlock()
		var tentative []networkPolicyNFQObservation
		transferred := false
		defer func() {
			if !transferred {
				closeViews(tentative)
				mu.Lock()
				invalid = true // Includes panic before successful completion.
				mu.Unlock()
			}
		}()
		callbackErr = networkPolicyNFQReadContext(parent, child, execution)
		if callbackErr == nil {
			callbackErr = current(child)
		}
		if callbackErr == nil {
			tentative, callbackErr = read(child)
			callbackErr = errors.Join(callbackErr, current(child), networkPolicyNFQReadContext(parent, child, execution))
		}
		mu.Lock()
		finished = true
		if open {
			published, bodyErr, transferred = tentative, callbackErr, true
		} else {
			// A defective observer returned before its admitted reader joined.
			// It cannot publish a late view into an already returned result.
			callbackErr = errors.Join(callbackErr, ErrNetworkPolicyConsumers)
		}
		mu.Unlock()
		return callbackErr
	})
	mu.Lock()
	open = false // Revoke admission before any closing callback or return.
	complete := entered && finished && !invalid
	result, published = published, nil
	originalErr := bodyErr
	mu.Unlock()
	if !complete {
		originalErr = errors.Join(originalErr, ErrNetworkPolicyConsumers)
	}
	err := errors.Join(outer, originalErr, current(parent), parent.Err())
	if err != nil {
		return nil, err
	}
	keep = true
	return result, nil
}

func networkPolicyNFQReadContext(parent, child context.Context, execution *nfqws2ActiveExecution) error {
	if nfqws2ActiveOperation(parent) != nil || nfqws2ActiveOperation(child) != nil || execution == nil || child.Value(nfqws2ActiveExecutionKey{}) != execution || parent.Value(nfqws2ActiveExecutionKey{}) != execution {
		return ErrNetworkPolicyConsumers
	}
	outer, _ := parent.Deadline()
	inner, _ := child.Deadline()
	// A borrowed receipt is the same original COMMON writer, never a copied
	// marker or a substitute session supplied by an observer callback.
	parentRaw, childRaw := parent.Value(policyEffectReceiptBorrowKey{}), child.Value(policyEffectReceiptBorrowKey{})
	parentBorrow, parentOK := parentRaw.(*policyEffectReceiptBorrow)
	childBorrow, childOK := childRaw.(*policyEffectReceiptBorrow)
	if inner.After(outer) || (parentRaw != nil && !parentOK) || (childRaw != nil && !childOK) || parentBorrow != childBorrow || child.Value(nfqwsRetiredInventoryKey{}) != nil || child.Value(nfqwsProbeCleanupKey{}) != nil {
		return ErrNetworkPolicyConsumers
	}
	return nil
}
