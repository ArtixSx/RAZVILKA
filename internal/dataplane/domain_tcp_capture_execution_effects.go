package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// During the SAME synchronous COMMON writer, its original borrow observes
// authored per-step states without recursively acquiring the permanent lock.
// External readers require the complete acknowledged receipt. Exact foreign
// rows while merely planned, pending unknowns, and cleanup never disappear
// into the counterfactual baseline view.
func (r *domainTCPCaptureExecutionResource) counterfactualRows(ctx context.Context, rows []backendInventoryRow) ([]backendInventoryRow, error) {
	if err := r.registered(ctx); err != nil {
		return nil, err
	}
	borrow, present, err := observeBorrowedPolicyEffects(ctx, r.effects, r.root)
	if err != nil {
		return nil, err
	}
	if present {
		defer borrow.close()
		states := borrow.states
		if borrow.absent {
			states = make([]string, len(r.effects.Effects))
			for i := range states {
				states[i] = "planned"
			}
		}
		if err := domainTCPCaptureReceiptMatchesRows(rows, r.effects, states); err != nil {
			return nil, err
		}
		filtered, err := domainTCPCaptureBaselineRows(rows, r.effects)
		return filtered, errors.Join(err, borrow.current(ctx), r.registered(ctx))
	}
	// A never-opened COMMON child has neither a ledger nor a marker. Missing
	// only one is an interrupted/foreign publication, never clean absence.
	if r.receiptAbsent() == nil {
		states := make([]string, len(r.effects.Effects))
		for i := range states {
			states[i] = "planned"
		}
		if err := domainTCPCaptureReceiptMatchesRows(rows, r.effects, states); err != nil {
			return nil, err
		}
		filtered, err := domainTCPCaptureBaselineRows(rows, r.effects)
		return filtered, errors.Join(err, r.receiptAbsent(), r.registered(ctx))
	}
	receipt, err := observeNetworkPolicyEffects(ctx, r.effects, r.root, policyAdditionOptions{})
	defer receipt.close()
	if err != nil {
		return nil, err
	}
	status := receipt.status
	if !status.Complete || status.Unknown || status.Removed || status.Promoted || status.Added != len(r.effects.Effects) || status.Pending != 0 || status.Cleaned != 0 {
		return nil, ErrDomainPolicyTCPConsumer
	}
	states := make([]string, len(r.effects.Effects))
	for i := range states {
		states[i] = "added"
	}
	if err := domainTCPCaptureReceiptMatchesRows(rows, r.effects, states); err != nil {
		return nil, err
	}
	filtered, err := domainTCPCaptureBaselineRows(rows, r.effects)
	return filtered, errors.Join(err, receipt.current(), r.registered(ctx))
}

func (r *domainTCPCaptureExecutionResource) receiptAbsent() error {
	if r == nil || r.process == nil || r.process.scope == nil || r.process.scope.owned == nil {
		return ErrDomainPolicyTCPConsumer
	}
	for _, name := range []string{policyAdditionFile, policyAdditionLock} {
		if _, err := r.process.scope.owned.Stat(filepath.Join(r.relative, name)); !errors.Is(err, os.ErrNotExist) {
			return ErrDomainPolicyTCPConsumer
		}
	}
	return nil
}

func domainTCPCaptureReceiptMatchesRows(rows []backendInventoryRow, plan PolicyEffectPlan, states []string) error {
	if len(states) != len(plan.Effects) {
		return ErrDomainPolicyTCPConsumer
	}
	for i, state := range states {
		count, err := domainTCPCapturePresence(rows, plan, i)
		if err != nil {
			return err
		}
		switch state {
		case "added":
			if count != 1 {
				return ErrDomainPolicyTCPConsumer
			}
		case "planned", "intent":
			if count != 0 {
				return ErrDomainPolicyTCPConsumer
			}
		default:
			return ErrDomainPolicyTCPConsumer
		}
	}
	return nil
}

func (r *domainTCPCaptureExecutionResource) read(ctx context.Context) (backendInventorySnapshot, error) {
	if err := r.current(ctx); err != nil {
		return backendInventorySnapshot{}, err
	}
	view, err := r.backend.Read(ctx, r.tools.Identity)
	if err != nil {
		return backendInventorySnapshot{}, err
	}
	if err := view.requireLANBackendCoverage(); err != nil {
		return backendInventorySnapshot{}, err
	}
	if view.Scope.Network != r.tools.Identity {
		return backendInventorySnapshot{}, ErrDomainPolicyTCPConsumer
	}
	return view, r.current(ctx)
}

// Capture cannot precede its SAME original standby baseline. Uncertain adds
// are retained in COMMON; this producer does not infer deletion authority
// from an expired lifetime or a matching effects receipt.
func (r *domainTCPCaptureExecutionResource) prepare(ctx context.Context, baseline *syntheticBaselineExecutionResource) error {
	if err := r.local(ctx); err != nil {
		return err
	}
	if baseline == nil || baseline.self != baseline || baseline.binding != r.process.material.binding || baseline.mapping != r.mapping || baseline.capture != r.capture || baseline.backend != r.backend || baseline.tools != r.tools {
		return ErrDomainPolicyTCPConsumer
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return r.failed
	}
	if err := baseline.currentBaseline(ctx); err != nil {
		return err
	}
	if r.started {
		return r.checkPrepared(ctx)
	}
	if err := r.current(ctx); err != nil {
		return err
	}
	r.started = true
	runtime := PolicyEffectRuntime{Runner: &domainTCPCaptureEffectRunner{resource: r}, Tools: PolicyEffectTools{IPTables: r.tools.IPTables}, Guard: func(c context.Context, _ int) error { return errors.Join(r.current(c), baseline.currentBaseline(c)) },
		Preflight: func(c context.Context) error {
			view, err := r.read(c)
			if err != nil {
				return err
			}
			for i := range r.effects.Effects {
				count, err := domainTCPCapturePresence(view.Rows, r.effects, i)
				if err != nil || count != 0 {
					return ErrDomainPolicyTCPConsumer
				}
			}
			return baseline.currentBaseline(c)
		},
		ExactPresence: func(c context.Context, i int) (int, error) {
			view, err := r.read(c)
			if err != nil {
				return 0, err
			}
			return domainTCPCapturePresence(view.Rows, r.effects, i)
		},
		BeforeDelete: func(context.Context, int) error { return dnscontrol.ErrSyntheticDNSTransitionPending }}
	if err := ApplyPolicyEffectsWithReceipt(ctx, runtime, r.effects, r.root); err != nil {
		r.failed = errors.Join(ErrPolicyAdditionUnknown, err)
		return r.failed
	}
	if err := errors.Join(r.checkPrepared(ctx), baseline.currentBaseline(ctx)); err != nil {
		r.failed = errors.Join(ErrPolicyAdditionUnknown, err)
		return r.failed
	}
	s := r.process.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.execution.Resources {
		record := &s.execution.Resources[i]
		if record.ID == filepath.Base(r.relative) {
			if record.Phase != "planned" {
				return ErrDomainPolicyTCPConsumer
			}
			record.Phase = "capture-prepared"
			return s.persist()
		}
	}
	return ErrDomainPolicyTCPConsumer
}

func (r *domainTCPCaptureExecutionResource) checkPrepared(ctx context.Context) error {
	if err := r.current(ctx); err != nil {
		return err
	}
	receipt, err := observeNetworkPolicyEffects(ctx, r.effects, r.root, policyAdditionOptions{})
	defer receipt.close()
	status := receipt.status
	if err != nil || !status.Complete || status.Unknown || status.Removed || status.Promoted || status.Added != len(r.effects.Effects) || status.Pending != 0 || status.Cleaned != 0 {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	view, err := r.read(ctx)
	if err != nil {
		return err
	}
	if err := domainTCPCapturePreparedInventory(view.Rows, r.effects); err != nil {
		return err
	}
	return errors.Join(r.current(ctx), receipt.current())
}

type domainTCPCaptureEffectRunner struct {
	resource *domainTCPCaptureExecutionResource
}

func (*domainTCPCaptureEffectRunner) syntheticDNSCommandAdmission() {}
func (runner *domainTCPCaptureEffectRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if runner == nil || runner.resource == nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	if err := runner.resource.current(ctx); err != nil {
		return nil, err
	}
	return runner.resource.tools.Runner.RunSyntheticDNS(ctx, runner, name, args...)
}
func (runner *domainTCPCaptureEffectRunner) WithStart(ctx context.Context, name string, args []string, review string, begin func() error) error {
	if runner == nil || runner.resource == nil || begin == nil {
		return ErrDomainPolicyTCPConsumer
	}
	r := runner.resource
	if err := r.local(ctx); err != nil {
		return err
	}
	if name != r.tools.IPTables || review != r.tools.ReviewSHA256 {
		return ErrDomainPolicyTCPConsumer
	}
	invocation, err := observePolicyEffectCommandInvocation(ctx, r.effects, r.root, name, args)
	cleanup := ctx.Value(domainTCPCaptureCleanupKey{}) == r
	if err != nil || invocation == nil || invocation.cleanup != cleanup {
		return ErrDomainPolicyTCPConsumer
	}
	wanted := r.effects.Effects[invocation.index].Add
	if cleanup {
		wanted = r.effects.Effects[invocation.index].Delete
	}
	if !reflect.DeepEqual(args, wanted) {
		return ErrDomainPolicyTCPConsumer
	}
	s := r.process.scope
	s.startMu.RLock()
	defer s.startMu.RUnlock()
	return invocation.withStart(ctx, func() error {
		if err := r.registered(ctx); err != nil {
			return err
		}
		var err error
		if cleanup {
			err = r.process.material.control.WithCleanupStart(ctx, r.process.material.cleanup, begin)
		} else {
			err = r.process.material.control.WithStart(ctx, begin)
		}
		return errors.Join(err, r.registered(ctx))
	})
}
