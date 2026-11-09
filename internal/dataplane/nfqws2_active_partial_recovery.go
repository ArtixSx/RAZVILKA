package dataplane

import (
	"context"
	"errors"
	"reflect"
)

func (b *NFQWSScopedBinding) applyOriginalPolicyEffects(ctx context.Context, p *NFQWSScopedPlan, runtime PolicyEffectRuntime, plan PolicyEffectPlan, root string) error {
	if b.activeReadback == nil {
		return applyPolicyEffects(ctx, runtime, plan, root, b.options)
	}
	e, err := b.activeReadbackOwner(ctx, p)
	if err != nil || e.binding != b || e.resource.Root() != root || e.panel == nil || e.panel.Err() != nil {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	c := &nfqwsPolicyRecovery{execution: e, index: -1}
	c.self = c
	c.mu.Lock()
	defer c.mu.Unlock()
	e.mu.Lock()
	if e.partialRecovery != nil {
		e.mu.Unlock()
		return ErrPolicyAdditionUnknown
	}
	e.partialRecovery = c
	e.mu.Unlock()
	options := nfqwsOriginalRecoveryOptions(e, b.options)
	err = applyPolicyEffectsWithOriginalRecovery(ctx, runtime, plan, root, options, nil, c)
	if !c.retained {
		c.closed = true // Ordinary Apply already closed its original writer.
		e.mu.Lock()
		e.partialRecovery = nil
		e.mu.Unlock()
		return err
	}
	// Source shutdown only. An expired forward request must retain recovery.
	// No execution/material/borrow lock is held while waiting for this mutex.
	c.shutdownStop = context.AfterFunc(e.panel, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.close()
	})
	return err
}

func (e *nfqws2ActiveExecution) rollback(ctx context.Context) error {
	if e == nil {
		return ErrNFQWSScopedOwner
	}
	e.mu.Lock()
	c := e.partialRecovery
	e.mu.Unlock()
	if c == nil {
		return e.rollbackOriginal(ctx)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.self != c || c.execution != e || !c.retained || c.closed || c.session == nil || c.entered || c.fenced || ctx == nil || ctx.Value(nfqws2ActiveExecutionKey{}) != e {
		return ErrPolicyAdditionUnknown
	}
	scope := &nfqwsRecoveryScope{owner: c}
	scope.self = scope
	c.scope.Store(scope)
	defer func() {
		scope.closed.Store(true)
		scope.readers.Lock()
		c.scope.Store(nil)
		scope.readers.Unlock()
	}()
	ctx = context.WithValue(ctx, nfqwsPolicyRecoveryKey{}, scope)
	ctx = context.WithValue(ctx, policyEffectReceiptBorrowKey{}, c.session.borrow)
	if err := e.rollbackOriginal(ctx); err != nil {
		return err
	}
	c.close() // Only after original native/COMMON/LAN/resource retirement.
	e.mu.Lock()
	e.partialRecovery = nil
	e.mu.Unlock()
	return nil
}

func (e *nfqws2ActiveExecution) originalRecovery(ctx context.Context) (*nfqwsPolicyRecovery, error) {
	raw := ctx.Value(nfqwsPolicyRecoveryKey{})
	if raw == nil {
		return nil, nil
	}
	scope, ok := raw.(*nfqwsRecoveryScope)
	if !ok || scope == nil || scope.self != scope || scope.owner == nil {
		return nil, ErrPolicyAdditionUnknown
	}
	c := scope.owner
	if c.self != c || !c.scopeCurrent(ctx) || c.execution != e || e.partialRecovery != c || c.closed || !c.retained || c.entered || c.fenced || c.session == nil || e.resource == nil || e.binding == nil || c.session.path != e.resource.Root() || !reflect.DeepEqual(c.session.plan, e.resource.Plan().mixed) || ctx.Value(policyEffectReceiptBorrowKey{}) != c.session.borrow || ctx.Value(nfqws2ActiveExecutionKey{}) != e {
		return nil, ErrPolicyAdditionUnknown
	}
	return c, nil
}

// Runs after the original Stop/sole Wait, BEFORE one-use native retirement.
// It changes no kernel state and grants no delete of the never-issued effect.
func (e *nfqws2ActiveExecution) settleNeverIssuedPolicy(ctx context.Context) error {
	c, err := e.originalRecovery(ctx)
	if err != nil || c == nil {
		return err
	}
	return c.settleNeverIssued(ctx, func() error { return e.verifyNeverIssuedPrefix(ctx, c) })
}

// The only production caller supplies the original complete-inventory proof
// above; the callback is private and cannot be supplied by API/DTO callers.
func (c *nfqwsPolicyRecovery) settleNeverIssued(ctx context.Context, verify func() error) error {
	if c == nil || c.self != c || !c.retained || c.entered || c.closed || c.fenced || verify == nil {
		return ErrPolicyAdditionUnknown
	}
	if err := c.finishPublication(ctx); err != nil {
		return err
	}
	s := c.session
	if c.index < 0 || c.index >= len(s.doc.Steps) || s.doc.Phase != "active" {
		return ErrPolicyAdditionUnknown
	}
	if c.settled {
		if s.doc.Steps[c.index].State != "removed" || s.status().Unknown {
			return ErrPolicyAdditionUnknown
		}
		if err := verify(); err != nil {
			return err
		}
		return c.documentCurrent(ctx)
	}
	for i, step := range s.doc.Steps {
		wanted := "planned"
		if i < c.index {
			wanted = "added"
		} else if i == c.index {
			wanted = "intent"
		}
		if step.State != wanted {
			return ErrPolicyAdditionUnknown
		}
	}
	if err := verify(); err != nil {
		return err
	}
	before, checksum := c.publication, s.doc.Checksum
	s.doc.Steps[c.index].State = "removed"
	err := s.save(ctx)
	if c.publication != before {
		c.settled = true // Retry finishes this SAME authored publication.
	} else if !c.fenced {
		// Nothing was published by this attempt; retain the original intent.
		s.doc.Steps[c.index].State, s.doc.Checksum = "intent", checksum
	}
	if err != nil {
		return err
	}
	return c.documentCurrent(ctx)
}

func (e *nfqws2ActiveExecution) verifyNeverIssuedPrefix(ctx context.Context, c *nfqwsPolicyRecovery) error {
	p := e.resource.Plan()
	bookend := func() error {
		if err := e.cleanupCurrent(ctx); err != nil {
			return err
		}
		if _, err := e.process(ctx, p, true); err != nil {
			return err
		}
		if err := e.binding.checkQueue(ctx, p, nil); err != nil {
			return err
		}
		return c.documentCurrent(ctx)
	}
	// Each capture is a new complete both-family inventory with its original
	// source/owner bookends. No count or foreign-reference result is reused.
	for range 2 {
		if err := bookend(); err != nil {
			return err
		}
		image, err := e.binding.readFinalRules(ctx, p)
		if err != nil {
			return err
		}
		counts, err := e.binding.ruleCountsImage(p, image, nfqwsScopedCleanup)
		if err != nil || len(counts) != len(c.session.plan.Effects) {
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
		for i, count := range counts {
			wanted := 0
			if i < c.index {
				wanted = 1
			}
			if count != wanted {
				return ErrPolicyAdditionUnknown
			}
		}
		if err := bookend(); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (e *nfqws2ActiveExecution) removeOriginalPolicy(ctx context.Context) error {
	c, err := e.originalRecovery(ctx)
	if err != nil {
		return err
	}
	if c == nil {
		return e.binding.Remove(ctx, e.resource.Plan(), e.resource.Root())
	}
	if !c.settled || c.needsSync || c.pending != nil {
		return ErrPolicyAdditionUnknown
	}
	if err := c.documentCurrent(ctx); err != nil {
		return err
	}
	p := e.resource.Plan()
	runtime, plan, err := e.binding.prepareOriginalRemove(p)
	if err != nil || !reflect.DeepEqual(plan, c.session.plan) {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	if err := e.binding.checkProcess(ctx, p, true); err != nil {
		return err
	}
	if err := e.binding.readback(ctx, p, nfqwsScopedCleanup, -1); err != nil {
		return err
	}
	if err := c.session.removeKnownEffects(ctx, runtime); err != nil {
		return err
	}
	return e.binding.VerifyInactive(ctx, p, e.resource.Root())
}
