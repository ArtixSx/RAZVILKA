package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
)

func (r *domainTCPBaselineExecutionResource) checkPrepared(ctx context.Context) error {
	if err := r.registered(ctx); err != nil {
		return err
	}
	receipt, err := observeNetworkPolicyEffects(ctx, r.effects, r.root, policyAdditionOptions{})
	defer receipt.close()
	s := receipt.status
	if err != nil || !s.Complete || s.Unknown || s.Removed || s.Promoted || s.Added != len(r.effects.Effects) || s.Pending != 0 || s.Cleaned != 0 {
		return errors.Join(ErrDomainTCPBaselineKernel, err)
	}
	if err := r.kernel.Current(ctx); err != nil {
		return err
	}
	return errors.Join(receipt.current(), r.registered(ctx))
}

func (r *domainTCPBaselineExecutionResource) effectCounts(ctx context.Context) ([]int, error) {
	if err := r.registered(ctx); err != nil {
		return nil, err
	}
	c := r.kernel.capture
	spec := r.definition.flowSpec()
	image, err := r.kernel.reader.ReadDomainTCPBaseline(ctx, spec.Source.Addr(), spec.Target.Addr(), spec.Capture.Client.Interface)
	if err != nil {
		return nil, err
	}
	var view backendInventorySnapshot
	if ctx.Value(domainTCPBaselineCleanupKey{}) == r {
		view, err = c.backend.Read(ctx, c.tools.Identity)
		if err == nil {
			err = view.requireLANBackendCoverage()
		}
		if err == nil && view.Scope.Network != c.tools.Identity {
			err = ErrDomainTCPBaselineKernel
		}
	} else {
		view, err = c.read(ctx)
	}
	if err != nil {
		return nil, err
	}
	_, _, counts, err := domainTCPBaselineFlowReadback(image, view.Rows, spec)
	return counts, errors.Join(err, r.registered(ctx))
}

func (r *domainTCPBaselineExecutionResource) prepare(ctx context.Context) error {
	if err := r.registered(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failure != nil {
		return r.failure
	}
	if r.started {
		return r.checkPrepared(ctx)
	}
	if err := r.kernel.Current(ctx); err != nil {
		return err
	}
	r.started = true
	c := r.kernel.capture
	runtime := PolicyEffectRuntime{Runner: &domainTCPBaselineEffectRunner{r}, Tools: PolicyEffectTools{IP: c.tools.IP, IPTables: c.tools.IPTables}, Guard: func(c context.Context, _ int) error { return errors.Join(r.registered(c), r.kernel.Current(c)) },
		Preflight: func(c context.Context) error {
			counts, err := r.effectCounts(c)
			if err != nil {
				return err
			}
			for _, count := range counts {
				if count != 0 {
					return ErrDomainTCPBaselineKernel
				}
			}
			return r.kernel.Current(c)
		}, ExactPresence: func(c context.Context, i int) (int, error) {
			counts, err := r.effectCounts(c)
			if err != nil {
				return 0, err
			}
			return counts[i], nil
		}, BeforeDelete: func(context.Context, int) error { return ErrDomainTCPBaselineKernel }}
	if err := ApplyPolicyEffectsWithReceipt(ctx, runtime, r.effects, r.root); err != nil {
		r.failure = errors.Join(ErrPolicyAdditionUnknown, err)
		return r.failure
	}
	if err := r.checkPrepared(ctx); err != nil {
		r.failure = errors.Join(ErrPolicyAdditionUnknown, err)
		return r.failure
	}
	s := c.process.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.execution.Resources {
		record := &s.execution.Resources[i]
		if record.ID == filepath.Base(r.relative) {
			if record.Phase != "planned" {
				return ErrDomainTCPBaselineKernel
			}
			record.Phase = "prepared"
			return s.persist()
		}
	}
	return ErrDomainTCPBaselineKernel
}

type domainTCPBaselineEffectRunner struct {
	resource *domainTCPBaselineExecutionResource
}

func (*domainTCPBaselineEffectRunner) syntheticDNSCommandAdmission() {}
func (runner *domainTCPBaselineEffectRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if runner == nil || runner.resource == nil {
		return nil, ErrDomainTCPBaselineKernel
	}
	r := runner.resource
	cleanup := ctx.Value(domainTCPBaselineCleanupKey{}) == r
	if cleanup {
		if err := r.cleanupCurrent(ctx); err != nil {
			return nil, err
		}
	} else if err := r.kernel.Current(ctx); err != nil {
		return nil, err
	}
	return r.kernel.capture.tools.Runner.RunSyntheticDNS(ctx, runner, name, args...)
}
func (runner *domainTCPBaselineEffectRunner) WithStart(ctx context.Context, name string, args []string, review string, begin func() error) error {
	if runner == nil || runner.resource == nil || begin == nil {
		return ErrDomainTCPBaselineKernel
	}
	r := runner.resource
	if err := r.local(ctx); err != nil {
		return err
	}
	t := r.kernel.capture.tools
	if review != t.ReviewSHA256 {
		return ErrDomainTCPBaselineKernel
	}
	invocation, err := observePolicyEffectCommandInvocation(ctx, r.effects, r.root, name, args)
	cleanup := ctx.Value(domainTCPBaselineCleanupKey{}) == r
	if err != nil || invocation == nil || invocation.cleanup != cleanup || name != (PolicyEffectTools{IP: t.IP, IPTables: t.IPTables}).command(r.effects.Effects[invocation.index].Tool) {
		return errors.Join(ErrDomainTCPBaselineKernel, err)
	}
	wanted := r.effects.Effects[invocation.index].Add
	if cleanup {
		wanted = r.effects.Effects[invocation.index].Delete
	}
	if !reflect.DeepEqual(args, wanted) {
		return ErrDomainTCPBaselineKernel
	}
	s := r.kernel.capture.process.scope
	s.startMu.RLock()
	defer s.startMu.RUnlock()
	return invocation.withStart(ctx, func() error {
		if err := r.registered(ctx); err != nil {
			return err
		}
		var err error
		if cleanup {
			err = r.kernel.capture.process.material.control.WithCleanupStart(ctx, r.cleanup, begin)
		} else {
			err = r.kernel.capture.process.material.control.WithStart(ctx, begin)
		}
		return errors.Join(err, r.registered(ctx))
	})
}
