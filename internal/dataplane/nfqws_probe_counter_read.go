package dataplane

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Only the fixed suffix is enclosed: the complete opening capture and the
// admitted counter command have already returned on the original context.
// The original command's effect/start admission is never inside this scope.
func (e *nfqwsProbeExecution) counterSuffix(ctx context.Context, raw []byte, chain string, measurement *nfqwsBoundaryMeasurement) (uint64, error) {
	if e == nil || e.consumer == nil {
		return e.counterSuffixBody(ctx, raw, chain, measurement)
	}
	original, supported := e.consumer.inventory.reader.Runner.(nfqwsProbeToolObserver)
	if !supported || ctx != nil && ctx.Value(nfqwsProbeCleanupKey{}) != nil {
		return e.counterSuffixBody(ctx, raw, chain, measurement)
	}
	current, err := e.counterSuffixCurrent(ctx)
	if err != nil {
		return 0, err
	}
	identity, review := e.socket.identity, e.consumer.inventory.review
	return nfqwsProbeCounterSuffixOnce(ctx, func(c context.Context, use func(context.Context) error) error {
		return original.WithReadOnlyToolObservation(c, identity, review, use)
	}, current, func(c context.Context) (uint64, error) { return e.counterSuffixBody(c, raw, chain, measurement) })
}

// Associations only; none of these comparisons replaces a Current, receipt,
// process, source, kernel, version, or byte observation in the original body.
func (e *nfqwsProbeExecution) counterSuffixCurrent(parent context.Context) (func(context.Context) error, error) {
	if e == nil || e.self != e || e.consumer == nil || e.consumer.self != e.consumer || e.socket == nil || e.source == nil || e.runtime == nil || e.epoch == nil || e.resource == nil || e.resource.plan == nil || e.binding == nil {
		return nil, ErrNFQWSScopedOwner
	}
	c, socket, source, runtime, epoch, resource, binding := e.consumer, e.socket, e.source, e.runtime, e.epoch, e.resource, e.binding
	plan, scope := resource.plan, resource.scope
	runner, provider, review := c.inventory.reader.Runner, c.inventory.reader.Provider, c.inventory.review
	runtimeRunner, runtimeOwner, gate := c.runtimeRunner, c.runtimeOwner, c.gate
	tools, commandRunner := binding.Tools, binding.Runner
	identity, control, cleanup, consumption := socket.identity, c.control, e.cleanup, e.consumption
	ip4, ip6 := c.inventory.reader.IPTables, c.inventory.reader.IP6Tables
	current := func(ctx context.Context) error {
		if err := nfqwsProbeCounterSuffixContext(parent, ctx, e); err != nil {
			return err
		}
		if e.self != e || e.consumer != c || c.self != c || e.socket != socket || e.source != source || e.runtime != runtime || e.epoch != epoch || e.resource != resource || e.binding != binding || resource.plan != plan || resource.scope != scope ||
			c.inventory.reader.Provider != provider || c.provider != provider || c.inventory.review != review || !sameNetworkPolicyDependency(c.inventory.reader.Runner, runner) || c.inventory.reader.IPTables != ip4 || c.inventory.reader.IP6Tables != ip6 ||
			c.runtimeOwner != runtimeOwner || !sameNetworkPolicyDependency(c.runtimeRunner, runtimeRunner) || c.gate != gate || binding.Tools != tools || !sameNetworkPolicyDependency(binding.Runner, commandRunner) ||
			socket.identity != identity || c.control != control || e.cleanup != cleanup || e.consumption != consumption || !c.OwnsContext(ctx) {
			return ErrNFQWSScopedOwner
		}
		return nil
	}
	if err := current(parent); err != nil {
		return nil, err
	}
	return current, nil
}

func nfqwsProbeCounterSuffixContext(parent, child context.Context, e *nfqwsProbeExecution) error {
	if parent == nil || child == nil || e == nil {
		return ErrNFQWSScopedOwner
	}
	outer, bounded := parent.Deadline()
	inner, finite := child.Deadline()
	now := time.Now()
	if !bounded || !finite || !now.Before(outer) || !now.Before(inner) || inner.After(outer) || parent.Value(nfqwsProbeExecutionKey{}) != e || child.Value(nfqwsProbeExecutionKey{}) != e || parent.Value(nfqwsProbeCleanupKey{}) != nil || child.Value(nfqwsProbeCleanupKey{}) != nil {
		return ErrNFQWSScopedOwner
	}
	return errors.Join(parent.Err(), child.Err())
}

// The scalar is provisional until the original observer's closing returns.
// An early/aborting observer cannot leave an admitted comparison running.
func nfqwsProbeCounterSuffixOnce(ctx context.Context, observe func(context.Context, func(context.Context) error) error, current func(context.Context) error, read func(context.Context) (uint64, error)) (count uint64, result error) {
	if ctx == nil || observe == nil || current == nil || read == nil {
		return 0, ErrNFQWSScopedOwner
	}
	var mu sync.Mutex
	open, entered, complete, misuse := true, false, false, false
	var revoke context.CancelFunc
	var tentative uint64
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
				if cancel != nil {
					cancel()
				}
				<-done
			}
		}
		mu.Lock()
		bad, finished, err, n := misuse, complete, bodyErr, tentative
		mu.Unlock()
		result = errors.Join(result, err, current(ctx), ctx.Err())
		if !didEnter || !finished || bad {
			result = errors.Join(result, ErrNFQWSScopedOwner)
		}
		if result != nil {
			count = 0
		} else {
			count = n
		}
	}()
	result = observe(ctx, func(ownerCtx context.Context) error {
		mu.Lock()
		if !open || entered || ownerCtx == nil {
			misuse = true
			mu.Unlock()
			return ErrNFQWSScopedOwner
		}
		entered = true
		mu.Unlock()
		// Context methods may reenter, panic or Goexit. No local mutex spans
		// initialization, and even a failure here must release the joined reader.
		defer close(done)
		observed, cancel := context.WithCancel(ownerCtx)
		defer cancel()
		mu.Lock()
		revoke = cancel
		admitted := open && !misuse
		mu.Unlock()
		if !admitted {
			return ErrNFQWSScopedOwner
		}
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
		if ctx.Err() != nil {
			cancel()
		}
		err := current(observed)
		var n uint64
		if err == nil {
			n, err = read(observed)
			err = errors.Join(err, current(observed))
		}
		mu.Lock()
		tentative, bodyErr, complete = n, err, true
		mu.Unlock()
		return err
	})
	return 0, result
}
