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
	return r.readWithFiles(ctx, nil)
}
func (r *domainTCPCaptureExecutionResource) readWithFiles(ctx context.Context, files *xrayDomainTCPFileObservation) (backendInventorySnapshot, error) {
	if err := r.currentWithFiles(ctx, files); err != nil {
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
	if c := r.process.scope.domainSuccessor; c != nil {
		view.Rows, err = c.counterfactualRows(ctx, r.backend, view.Rows)
		if err != nil {
			return backendInventorySnapshot{}, err
		}
	}
	return view, r.currentWithFiles(ctx, files)
}

// Capture cannot precede its SAME original standby baseline. Uncertain adds
// are retained in COMMON; this producer does not infer deletion authority
// from an expired lifetime or a matching effects receipt.
func (r *domainTCPCaptureExecutionResource) prepare(ctx context.Context, baseline *syntheticBaselineExecutionResource) error {
	defer domainTCPMeasure("capture-prepare")(0)
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
	if err := baseline.currentBaselineInOriginalFileObservation(ctx); err != nil {
		return err
	}
	if r.started {
		return r.checkPrepared(ctx)
	}
	if err := r.current(ctx); err != nil {
		return err
	}
	r.started = true
	runtime := PolicyEffectRuntime{Runner: &domainTCPCaptureEffectRunner{resource: r}, Tools: PolicyEffectTools{IPTables: r.tools.IPTables}, Guard: func(c context.Context, _ int) error {
		defer domainTCPMeasure("capture-add-guard")(0)
		return r.guardOriginalBaseline(c, baseline)
	},
		Preflight: func(c context.Context) error {
			return r.comparePreparation(c, baseline, domainPreparationPreflight)
		},
		ExactPresence: func(c context.Context, i int) (int, error) {
			count := 0
			err := r.observeTools(c, func(observed context.Context) error {
				// readWithFiles already bookends every actual kernel read with
				// the original complete process/material Current. Share only its
				// immutable executable bytes across those SAME two observations.
				return r.observePreAddFiles(observed, false, func(files *xrayDomainTCPFileObservation) error {
					view, err := r.readWithFiles(observed, files)
					if err != nil {
						return err
					}
					count, err = domainTCPCapturePresence(view.Rows, r.effects, i)
					return err
				})
			})
			if err != nil {
				return 0, err // No positive count survives a closing proof failure.
			}
			return count, nil
		},
		BeforeDelete: func(context.Context, int) error { return dnscontrol.ErrSyntheticDNSTransitionPending }}
	if err := applyDomainTCPOriginalEffects(ctx, runtime, r, baseline); err != nil {
		r.failed = errors.Join(ErrPolicyAdditionUnknown, err)
		return r.failed
	}
	// COMMON has returned from all actual mutations. This separate readonly
	// closing comparison cannot lend its view to any command admission.
	if err := r.comparePreparation(ctx, baseline, domainPreparationClosing); err != nil {
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
	return r.checkPreparedWithFiles(ctx, nil)
}
func (r *domainTCPCaptureExecutionResource) checkPreparedWithFiles(ctx context.Context, files *xrayDomainTCPFileObservation) error {
	if err := r.currentWithFiles(ctx, files); err != nil {
		return err
	}
	receipt, err := observeNetworkPolicyEffects(ctx, r.effects, r.root, policyAdditionOptions{})
	defer receipt.close()
	status := receipt.status
	if err != nil || !status.Complete || status.Unknown || status.Removed || status.Promoted || status.Added != len(r.effects.Effects) || status.Pending != 0 || status.Cleaned != 0 {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	if original, err := r.readOriginalPreparedWithFiles(ctx, files); original {
		if err != nil {
			return err
		}
		return errors.Join(receipt.current(), ctx.Err())
	}
	view, err := r.readWithFiles(ctx, files)
	if err != nil {
		return err
	}
	if err := domainTCPCapturePreparedInventory(view.Rows, r.effects); err != nil {
		return err
	}
	return errors.Join(r.currentWithFiles(ctx, files), receipt.current())
}

// Only the already-bound original kernel owner selects this pure read. Early
// preparation (before that owner exists), custom sources and all cleanup paths
// keep the original sequence. Malformed original associations never fall back.
func (r *domainTCPCaptureExecutionResource) originalPreparedReadSources(ctx context.Context) (*domainTCPBaselineCurrentSources, *domainTCPBaselineKernelOwner, bool, error) {
	if ctx == nil || ctx.Value(domainTCPBaselineCleanupKey{}) != nil || ctx.Value(domainTCPCaptureCleanupKey{}) != nil || ctx.Value(domainTCPFailureCleanupKey{}) != nil {
		return nil, nil, false, nil
	}
	if r == nil || r.self != r || r.capture == nil {
		return nil, nil, true, ErrDomainPolicyTCPConsumer
	}
	owner, original := r.capture.owner.(*DomainTCPOriginalScope)
	if !original {
		return nil, nil, false, nil
	}
	if owner == nil || owner.self != owner {
		return nil, nil, true, ErrDomainPolicyTCPConsumer
	}
	owner.mu.Lock()
	kernel, closed := owner.kernel, owner.closed
	same := owner.captureResource == r && owner.capture == r.capture && owner.process == r.process
	owner.mu.Unlock()
	if closed || !same {
		return nil, nil, true, ErrDomainPolicyTCPConsumer
	}
	if kernel == nil {
		return nil, nil, false, nil
	}
	if kernel.self != kernel || kernel.capture != r {
		return nil, nil, true, ErrDomainPolicyTCPConsumer
	}
	sources, supported, err := kernel.originalCurrentSources(ctx)
	if err != nil {
		return nil, nil, true, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	if !supported {
		return nil, nil, false, nil
	}
	if sources == nil || sources.resource != r || sources.owner != owner {
		return nil, nil, true, ErrDomainPolicyTCPConsumer
	}
	return sources, kernel, true, nil
}

// Comparison inputs only, not a current-process or source proof.
func (r *domainTCPCaptureExecutionResource) preparedReadInputsMatch(definition ExecutionDomainTCPCaptureDefinition, plan PolicyEffectPlan, digest, root, relative string, anchor os.FileInfo) bool {
	return r != nil && reflect.DeepEqual(r.definition, definition) && reflect.DeepEqual(r.effects, plan) && r.digest == digest && r.root == root && r.relative == relative && anchor != nil && r.anchor != nil && os.SameFile(anchor, r.anchor)
}

// This fixed variant moves only the pure row/plan predicate before the read's
// final full Current. It never shares a process observation across a callback.
// The preceding initial Current/receipt read and this read's opening remain
// separate. Generic readWithFiles is unchanged. No effect, publication, native
// Start or observer callback is introduced, and no comparison escapes this call.
func (r *domainTCPCaptureExecutionResource) readOriginalPreparedWithFiles(ctx context.Context, files *xrayDomainTCPFileObservation) (bool, error) {
	sources, kernel, original, err := r.originalPreparedReadSources(ctx)
	if err != nil || !original {
		return original, err
	}
	defer domainTCPMeasure("capture-prepared-read")(0) // Completed interval, not success.
	definition := r.definition.Clone()
	plan, err := compileDomainTCPCaptureEffects(definition.Process.Capture, definition.Process.Mapping)
	if err != nil {
		return true, err
	}
	digest, err := PolicyEffectPlanDigest(plan)
	if err != nil {
		return true, err
	}
	root, relative, anchor := r.root, r.relative, r.anchor
	association := func() error {
		if sources.resource != r || sources.current(ctx, kernel) != nil || !r.preparedReadInputsMatch(definition, plan, digest, root, relative, anchor) {
			return ErrDomainPolicyTCPConsumer
		}
		return ctx.Err()
	}
	if err := association(); err != nil {
		return true, err
	}
	// Keep the original read opening/backend/coverage/counterfactual ordering.
	if err := r.currentWithFiles(ctx, files); err != nil {
		return true, err
	}
	view, err := r.backend.Read(ctx, r.tools.Identity)
	if err != nil {
		return true, err
	}
	if err := view.requireLANBackendCoverage(); err != nil {
		return true, err
	}
	if view.Scope.Network != r.tools.Identity {
		return true, ErrDomainPolicyTCPConsumer
	}
	if c := r.process.scope.domainSuccessor; c != nil {
		view.Rows, err = c.counterfactualRows(ctx, r.backend, view.Rows)
		if err != nil {
			return true, err
		}
	}
	// Even invalid rows or association drift must retain the original full
	// closing; only earlier read failures had the original short-circuit.
	prepared := errors.Join(association(), domainTCPCapturePreparedInventory(view.Rows, plan))
	closing := r.currentWithFiles(ctx, files)
	return true, errors.Join(prepared, closing, association(), ctx.Err())
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
