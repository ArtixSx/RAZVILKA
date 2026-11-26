package dataplane

import (
	"context"
	"errors"
	"reflect"
	"slices"
)

// Pure local owner comparison, used under the actual held descriptor's locks.
// No provider/Current callbacks or source locks may run at that boundary.
func nfqwsProbeCommandOwner(ctx context.Context, name string, args []string, digest string) (*nfqwsProbeExecution, int, bool, error) {
	if ctx == nil {
		return nil, 0, false, ErrNFQWSScopedOwner
	}
	e, ok := ctx.Value(nfqwsProbeExecutionKey{}).(*nfqwsProbeExecution)
	if !ok || e == nil || e.self != e || !e.open.Load() || e.consumer == nil || e.consumer.self != e.consumer || e.binding == nil || e.resource == nil || e.consumer.inventory.review != digest || !lanPolicyHash(digest) || e.resource.plan.spec.Probe == nil || !reflect.DeepEqual(e.spec, e.resource.plan.spec) || e.resource.scope.manager != e.consumer.manager || e.resource.scope.adapterOwner != e.consumer.adapter || !sameNetworkPolicyDependency(e.binding.Runner, e.consumer.runtimeRunner) || e.consumer.gate.Binding.Runtime != e.consumer.runtimeOwner || !sameNetworkPolicyDependency(e.consumer.runtimeOwner.Runner, e.consumer.runtimeRunner) {
		return nil, 0, false, ErrNFQWSScopedOwner
	}
	index, cleanup := -1, false
	for i, effect := range e.resource.plan.mixed.Effects {
		if name != e.binding.Tools.command(effect.Tool) {
			continue
		}
		add, remove := slices.Equal(args, effect.Add), slices.Equal(args, effect.Delete)
		if add && remove || (add || remove) && index != -1 {
			return nil, 0, false, ErrNFQWSScopedOwner
		}
		if add || remove {
			index, cleanup = i, remove
		}
	}
	if index < 0 {
		return nil, 0, false, ErrNFQWSScopedOwner
	}
	r := e.resource
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	i, err := r.matching(r.binding)
	if err != nil || !r.startACK || !r.preparedUsed || !cleanup && r.scope.execution.Resources[i].Phase != "capture-ready" {
		return nil, 0, false, errors.Join(ErrNFQWSScopedOwner, err)
	}
	if cleanup {
		if ctx.Value(nfqwsProbeCleanupKey{}) != e || e.processResult == nil || !e.processResult.Acknowledged || !e.processResult.Receipt.WaitECHILD || nfqws2ValidateManagedLease(*e.processResult) != nil {
			return nil, 0, false, ErrNFQWSScopedOwner
		}
	} else if ctx.Value(nfqwsProbeCleanupKey{}) != nil || e.processResult != nil {
		return nil, 0, false, ErrNFQWSScopedOwner
	}
	if err := r.scope.checkOriginalOwner(ctx, &executionTransitResource{relative: r.relative, anchor: r.anchor}, !cleanup, cleanup); err != nil {
		return nil, 0, false, err
	}
	return e, index, cleanup, nil
}

func withNFQWSProbeCommandStart(ctx context.Context, name string, args []string, digest string, begin func() error) error {
	if begin == nil {
		return ErrNFQWSScopedOwner
	}
	frozen := slices.Clone(args)
	e, index, cleanup, err := nfqwsProbeCommandOwner(ctx, name, frozen, digest)
	if err != nil {
		return err
	}
	invocation, err := observePolicyEffectCommandInvocation(ctx, e.resource.plan.mixed, e.resource.root, name, frozen)
	if err != nil || invocation == nil || invocation.index != index || invocation.cleanup != cleanup {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return invocation.withStart(ctx, func() error {
		opening, i, c, err := nfqwsProbeCommandOwner(ctx, name, frozen, digest)
		if err != nil || opening != e || i != index || c != cleanup {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		if cleanup {
			err = e.consumer.control.WithCleanupStart(ctx, e.cleanup, begin)
		} else {
			if e.consumption == nil {
				return ErrNFQWSScopedOwner
			}
			// Epoch precedes control, matching Finish's epoch->source->control
			// ordering. Only short control admission + actual Start is enclosed.
			err = e.consumption.WithStart(ctx, func() error { return e.consumer.control.WithStart(ctx, begin) })
		}
		closing, i, c, closeErr := nfqwsProbeCommandOwner(ctx, name, frozen, digest)
		if closeErr != nil || closing != e || i != index || c != cleanup {
			return errors.Join(err, ErrNFQWSScopedOwner, closeErr)
		}
		return err
	})
}

func (r *ManagedNFQWSProbeConsumer) ProbeCounterCommandCurrent(ctx context.Context, name string, args []string, digest string) error {
	if !r.OwnsContext(ctx) {
		return ErrNFQWSScopedOwner
	}
	e := ctx.Value(nfqwsProbeExecutionKey{}).(*nfqwsProbeExecution)
	if e.resource == nil || e.binding == nil || e.resource.plan.spec.Probe == nil || e.processResult != nil || digest != r.inventory.review || name != r.inventory.reader.IPTables || len(e.resource.plan.resources.Chains) != 1 || !slices.Equal(args, []string{"-t", "mangle", "-L", e.resource.plan.resources.Chains[0], "-n", "-v", "-x"}) {
		return ErrNFQWSScopedOwner
	}
	e.resource.scope.mu.Lock()
	defer e.resource.scope.mu.Unlock()
	i, err := e.resource.matching(e.resource.binding)
	if err != nil || !e.resource.startACK || e.resource.scope.execution.Resources[i].Phase != "capture-ready" {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return e.resource.scope.checkOriginalOwner(ctx, &executionTransitResource{relative: e.resource.relative, anchor: e.resource.anchor}, true, false)
}

func (r *ManagedNFQWSProbeConsumer) WithProbeCounterCommandStart(ctx context.Context, name string, args []string, digest string, begin func() error) error {
	if begin == nil {
		return ErrNFQWSScopedOwner
	}
	if err := r.ProbeCounterCommandCurrent(ctx, name, args, digest); err != nil {
		return err
	}
	err := r.control.WithStart(ctx, begin)
	return errors.Join(err, r.ProbeCounterCommandCurrent(ctx, name, args, digest))
}
