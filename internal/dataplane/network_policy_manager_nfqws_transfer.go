package dataplane

import (
	"context"
	"errors"
	"path/filepath"
)

type nfqwsExecutionActiveReadbackMode string

const (
	nfqwsExecutionActiveBeforeCapture  nfqwsExecutionActiveReadbackMode = "before-capture"
	nfqwsExecutionActiveBeforeTransfer nfqwsExecutionActiveReadbackMode = "before-transfer"
)

// Installed only by the actual NFQ owner. Its live lease3/process observation,
// concrete typed queue, LAN and common capture receipt checks run independently
// of this borrowed registrar. No serialized observation installs this reader.
type nfqwsExecutionActiveReadback func(context.Context, *NFQWSScopedPlan, string, nfqwsExecutionActiveReadbackMode, NFQWSActiveObservation) error
type nfqwsExecutionActiveReadbackKey struct{}

// Internal owner-only binding, BEFORE BeforeStart. The temporary health/canary
// issuer cannot become an active owner, even with an identical command hash.
func (r *NFQWSExecutionResource) configureActive(ctx context.Context, command nfqws2ActiveProcessCommand) error {
	if r == nil || r.scope == nil || ctx == nil {
		return ErrNFQWSScopedOwner
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	adapter, realAdapter := r.scope.adapterOwner.(*NFQWS2Adapter)
	owner, ownerErr := "", error(nil)
	if realAdapter && adapter != nil {
		owner, ownerErr = adapter.owner()
	}
	i, err := r.matching(r.binding)
	if err != nil || r.activeCommand != nil || r.beforeUsed || r.scope.execution.ResourcePlanID != "" ||
		r.scope.execution.Resources[i].Phase != "planned" || r.scope.execution.PlanID != r.scope.plan.PlanID ||
		!realAdapter || adapter == nil || ownerErr != nil || command.Owner != owner || adapter.StateRoot != filepath.Join(r.scope.manager.StateRoot, "runtime", r.scope.adapter) || command.StateRoot != adapter.StateRoot || nfqws2ActiveCommandMatchesSpec(command, r.plan.Spec()) != nil {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	readback, ok := ctx.Value(nfqwsExecutionActiveReadbackKey{}).(nfqwsExecutionActiveReadback)
	if !ok || readback == nil {
		return ErrNFQWSScopedOwner
	}
	if err := r.check(ctx, true); err != nil {
		return err
	}
	command = command.clone()
	r.activeCommand, r.activeReadback = &command, readback
	r.scope.execution.Resources[i].NFQWS.Mode = nfqws2ActiveProcessMode
	return r.scope.persist()
}

// PreparedActive consumes a concrete owner's running observation through its
// separately installed lease3 reader. It never invokes the old lease2 reader
// or treats a supplied Observation as a running-child/capture permission.
func (r *NFQWSExecutionResource) PreparedActive(ctx context.Context, binding NFQWSExecutionBinding, observation NFQWSActiveObservation) error {
	if r == nil || r.scope == nil || r.activeCommand == nil || r.activeReadback == nil {
		return ErrNFQWSScopedOwner
	}
	if err := func() error {
		r.scope.mu.Lock()
		defer r.scope.mu.Unlock()
		i, err := r.matching(binding)
		if err != nil || !r.startACK || r.preparedUsed || r.scope.execution.Resources[i].Phase != "process-pending" {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		if err := validateExecutionNFQWSObservation(*r.scope.execution, r.scope.execution.Resources[i], r.plan, observation); err != nil {
			return err
		}
		if err := r.check(ctx, true); err != nil {
			return err
		}
		r.preparedUsed = true
		return nil
	}(); err != nil {
		return err
	}
	if err := r.activeReadback(ctx, r.plan, r.root, nfqwsExecutionActiveBeforeCapture, observation); err != nil {
		return err
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	i, err := r.matching(binding)
	if err != nil {
		return err
	}
	if err := r.check(ctx, true); err != nil {
		return err
	}
	r.activeObservation = &observation
	r.scope.execution.Resources[i].Phase = "capture-ready"
	return r.scope.persist()
}

// A: independently prove the SAME running owner/capture/receipt BEFORE any
// desired-state CAS or committed-plan publication, then durably write intent
// to BOTH existing records. Consumed on the first attempt; it cannot be replayed.
func (r *NFQWSExecutionResource) BeginTransfer(ctx context.Context) error {
	if r == nil || r.scope == nil || r.activeCommand == nil || r.activeReadback == nil {
		return ErrNFQWSScopedOwner
	}
	var observation NFQWSActiveObservation
	if err := func() error {
		r.scope.mu.Lock()
		defer r.scope.mu.Unlock()
		i, err := r.matching(r.binding)
		if err != nil || r.transferUsed || r.activeObservation == nil || !r.startACK || !r.preparedUsed || r.scope.execution.Resources[i].Phase != "capture-ready" {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		if err := r.check(ctx, true); err != nil {
			return err
		}
		observation = *r.activeObservation
		if err := validateExecutionNFQWSObservation(*r.scope.execution, r.scope.execution.Resources[i], r.plan, observation); err != nil {
			return err
		}
		r.transferUsed = true
		return nil
	}(); err != nil {
		return err
	}
	if err := r.activeReadback(ctx, r.plan, r.root, nfqwsExecutionActiveBeforeTransfer, observation); err != nil {
		return err
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	i, err := r.matching(r.binding)
	if err != nil {
		return err
	}
	if err := r.check(ctx, true); err != nil {
		return err
	}
	r.scope.execution.Resources[i].Phase = "transfer-intent"
	return r.scope.persist()
}

// These are retained comparison records, never active-owner capabilities.
// Terminal ACTIVE remains refused until the separately sealed live owner
// final-ACK handle and exact original Manager transfer barrier are connected.
func validateExecutionNFQWSMode(execution Execution, resource ExecutionResource, plan *NFQWSScopedPlan) error {
	d := resource.NFQWS
	if d == nil {
		return ErrExecutionJournal
	}
	switch d.Mode {
	case "":
		if d.Observation != nil || resource.Phase == "transfer-intent" || resource.Phase == "transfer-ack" {
			return ErrExecutionJournal
		}
		return nil
	case nfqws2ActiveProcessMode:
		if d.NetworkIdentity == nil || d.Spec.NetworkIdentity == nil || execution.ResourcePlanID != "" || execution.State == "checking" || execution.State == "temporary-complete" {
			return ErrExecutionJournal
		}
	default:
		return ErrExecutionJournal
	}
	switch resource.Phase {
	case "planned", "process-pending", "capture-ready", "transfer-intent":
		if d.Observation != nil {
			return ErrExecutionJournal
		}
	case "transfer-ack", "active":
		if d.Observation == nil {
			return ErrExecutionJournal
		}
	case "closed", "removed":
		// Keep the original provisional identity after ambiguity/cleanup. The
		// saved record never supplies independent inactive proof or deletion.
	default:
		return ErrExecutionJournal
	}
	if d.Observation != nil {
		if err := validateExecutionNFQWSObservation(execution, resource, plan, *d.Observation); err != nil {
			return errors.Join(ErrExecutionJournal, err)
		}
	}
	return nil
}

func validateExecutionNFQWSObservation(execution Execution, resource ExecutionResource, plan *NFQWSScopedPlan, observed NFQWSActiveObservation) error {
	d := resource.NFQWS
	if d == nil || d.NetworkIdentity == nil || observed.NetworkIdentity != *d.NetworkIdentity || observed.NetworkIdentity.Validate() != nil {
		return ErrNetworkPolicyIdentity
	}
	want := NFQWSExecutionBinding{ExecutionID: execution.PlanID, PlanID: d.Plan.PlanID, PlanDigest: d.Plan.Digest,
		ResourceID: resource.ID, ResourceGeneration: resource.Generation, EffectsDigest: resource.EffectsDigest,
		SessionID: d.Spec.SessionID, CommandSHA256: d.Spec.CommandSHA256}
	if observed.Binding != want {
		return ErrNFQWSScopedOwner
	}
	return nfqwsScopedProcessProof(plan, NFQWSScopedProcessProof{SessionID: want.SessionID, CommandSHA256: want.CommandSHA256, Receipt: observed.Receipt, Child: observed.Child}, false)
}
