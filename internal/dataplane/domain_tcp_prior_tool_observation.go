package dataplane

import (
	"context"
	"errors"
	"sync"
)

// This is only a binding of the original readonly tool producer. It does not
// replace any retained-owner, receipt, process, namespace or kernel read.
type domainTCPPriorToolSource struct {
	entry      *domainTCPStandbyPoolEntry
	detached   *DomainTCPDetachedStandby
	owner      *DomainTCPOriginalScope
	capture    *domainTCPCaptureExecutionResource
	backend    *BackendInventory
	descriptor *SyntheticDNSCommandTools
	tools      SyntheticDNSCommandTools
	source     NFQWS2Runner
	ip6        string
	abi        backendNFTABI
}

func (s *domainTCPPriorToolSource) current(c *domainTCPGlobalSuccessor) error {
	if c == nil || s == nil || s.entry == nil || s.detached == nil || s.entry.detached != s.detached || s.detached.original != s.owner || s.detached.owner == nil || s.detached.owner.original != s.owner || s.owner == nil || s.owner.self != s.owner || s.capture == nil || s.capture.self != s.capture || s.backend == nil || s.descriptor == nil || !s.descriptor.valid() || *s.descriptor != s.tools {
		return ErrPolicyAdditionUnknown
	}
	o := s.owner
	o.mu.Lock()
	same := o.closed && o.standbyReady && o.captureResource == s.capture && o.process == s.capture.process && o.binding != nil && o.binding.scope != c.scope && o.backend == s.backend && o.tools.valid() && o.tools == s.tools && sameNetworkPolicyDependency(o.source, s.source)
	o.mu.Unlock()
	if !same || s.capture.backend != s.backend || s.capture.tools != s.descriptor || !sameNetworkPolicyDependency(s.backend.reader.Runner, s.source) || s.backend.reader.Provider != s.tools.Provider || s.backend.review != s.tools.ReviewSHA256 || s.backend.reader.IPTables != s.tools.IPTables || s.backend.reader.IP6Tables != s.ip6 || s.backend.reader.NFTABI != s.abi {
		return ErrPolicyAdditionUnknown
	}
	return nil
}

// Only the pure comparison between two journal writes is enclosed. The
// original producer revokes, joins and closes its complete tool bytes before
// returning to the publisher. In particular, this does not acquire the new
// scope/process mutexes or lend a tool marker across a journal mutation.
func (c *domainTCPGlobalSuccessor) comparePriorInToolObservation(ctx context.Context, after bool) error {
	fallback := func() error { return c.comparePriorInFileObservation(ctx, after) }
	if ctx == nil || c == nil || c.original() != nil || domainTCPHasPriorRead(ctx) {
		return ErrPolicyAdditionUnknown
	}
	if ctx.Value(domainTCPPreAddKey{}) != nil || ctx.Value(domainTCPGuardReadKey{}) != nil || ctx.Value(domainTCPBaselineCleanupKey{}) != nil || ctx.Value(domainTCPCaptureCleanupKey{}) != nil || ctx.Value(domainTCPFailureCleanupKey{}) != nil {
		return fallback()
	}
	entries, err := c.pool.originals()
	if err != nil {
		return err
	}
	sources := make([]domainTCPPriorToolSource, 0, len(entries))
	var observer domainTCPToolObserver
	for _, entry := range entries {
		if entry == nil || entry.detached == nil || entry.detached.original == nil {
			return ErrPolicyAdditionUnknown
		}
		o := entry.detached.original
		o.mu.Lock()
		capture, backend := o.captureResource, o.backend
		o.mu.Unlock()
		if capture == nil || capture.tools == nil || backend == nil {
			return ErrPolicyAdditionUnknown
		}
		original, ok := backend.reader.Runner.(domainTCPToolObserver)
		if !ok {
			return fallback() // Custom producers retain all original full checks.
		}
		s := domainTCPPriorToolSource{entry: entry, detached: entry.detached, owner: o, capture: capture, backend: backend, descriptor: capture.tools, tools: *capture.tools, source: backend.reader.Runner, ip6: backend.reader.IP6Tables, abi: backend.reader.NFTABI}
		if err := s.current(c); err != nil {
			return err
		}
		if len(sources) != 0 && (!sameNetworkPolicyDependency(s.source, sources[0].source) || s.tools.Provider != sources[0].tools.Provider || s.tools.Identity != sources[0].tools.Identity || s.tools.ReviewSHA256 != sources[0].tools.ReviewSHA256) {
			return fallback() // Never combine distinct original tool leases.
		}
		sources = append(sources, s)
		observer = original
	}
	association := func() error {
		if err := c.original(); err != nil {
			return err
		}
		current, err := c.pool.originals()
		if err != nil || len(current) != len(sources) {
			return errors.Join(ErrPolicyAdditionUnknown, err)
		}
		for i := range sources {
			if current[i] != sources[i].entry {
				return ErrPolicyAdditionUnknown
			}
			if err := sources[i].current(c); err != nil {
				return err
			}
		}
		return nil
	}
	if err := association(); err != nil {
		return err
	}
	tools := sources[0].tools
	result := domainTCPPriorToolComparison(ctx, func(parent context.Context, use func(context.Context) error) error {
		return observer.WithReadOnlyToolObservation(parent, tools.Identity, tools.ReviewSHA256, use)
	}, func(observed context.Context) error {
		if err := association(); err != nil {
			return err
		}
		return errors.Join(c.comparePriorInFileObservation(observed, after), association())
	})
	return errors.Join(result, association())
}

// Unlike a live baseline callback, a journal publisher normally has no
// execution registrar in its context. Preserve its absence; do not manufacture
// one merely to share immutable tool bytes. All private phase keys keep their
// original full-check path above.
func domainTCPPriorToolReadContext(parent, child context.Context) error {
	if xraySelectedTCPFinite(parent) != nil || xraySelectedTCPFinite(child) != nil {
		return ErrPolicyAdditionUnknown
	}
	outer, _ := parent.Deadline()
	inner, _ := child.Deadline()
	if inner.After(outer) || !sameNetworkPolicyDependency(parent.Value(syntheticExecutionRegistrarKey{}), child.Value(syntheticExecutionRegistrarKey{})) ||
		child.Value(domainTCPPreAddKey{}) != nil || child.Value(domainTCPGuardReadKey{}) != nil || domainTCPHasPriorRead(child) ||
		child.Value(domainTCPBaselineCleanupKey{}) != nil || child.Value(domainTCPCaptureCleanupKey{}) != nil || child.Value(domainTCPFailureCleanupKey{}) != nil {
		return ErrPolicyAdditionUnknown
	}
	return nil
}

// Keep the existing synchronous observation protocol without adding a scope
// registrar. Even an early return or panic cancels and joins the single read
// before the caller can resume its journal writer.
func domainTCPPriorToolComparison(ctx context.Context, observe func(context.Context, func(context.Context) error) error, read func(context.Context) error) (result error) {
	if domainTCPPriorToolReadContext(ctx, ctx) != nil || observe == nil || read == nil {
		return ErrPolicyAdditionUnknown
	}
	var mu sync.Mutex
	open, entered, complete, misuse := true, false, false, false
	var revoke context.CancelFunc
	var bodyErr error
	done := make(chan struct{})
	defer func() {
		mu.Lock()
		open = false
		didEnter, cancel := entered, revoke
		mu.Unlock()
		if didEnter {
			select {
			case <-done:
			default:
				mu.Lock()
				misuse = true
				mu.Unlock()
				cancel()
				<-done
			}
		}
		mu.Lock()
		defer mu.Unlock()
		result = errors.Join(result, bodyErr, ctx.Err())
		if !didEnter || !complete || misuse {
			result = errors.Join(result, ErrPolicyAdditionUnknown)
		}
	}()
	return observe(ctx, func(ownerCtx context.Context) error {
		mu.Lock()
		if !open || entered || ownerCtx == nil {
			misuse = true
			mu.Unlock()
			return ErrPolicyAdditionUnknown
		}
		entered = true
		observed, cancel := context.WithCancel(ownerCtx)
		revoke = cancel
		mu.Unlock()
		defer close(done)
		defer cancel()
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
		if ctx.Err() != nil {
			cancel()
		}
		err := domainTCPPriorToolReadContext(ctx, observed)
		if err == nil {
			err = errors.Join(read(observed), domainTCPPriorToolReadContext(ctx, observed))
		}
		mu.Lock()
		bodyErr, complete = err, true
		mu.Unlock()
		return err
	})
}
