package dataplane

import (
	"context"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Compact typed intent for the EXISTING common execution journal. It retains
// comparison coordinates only; it cannot recreate the original mapping,
// Manager, operation, physical lease, kernel/receipt or cleanup capability.
// Per-mapping records do not duplicate the entire potentially large Plan.
type ExecutionSyntheticBaselineDefinition struct {
	Schema          int                                       `json:"schema"`
	PlanID          string                                    `json:"plan_id"`
	PlanDigest      string                                    `json:"plan_digest"`
	DomainDigest    string                                    `json:"domain_digest"`
	Mapping         dnscontrol.SyntheticDNSMappingObservation `json:"mapping"`
	NetworkIdentity netidentity.Identity                      `json:"network_identity"`
}

func cloneExecutionSyntheticBaselineDefinition(d *ExecutionSyntheticBaselineDefinition) *ExecutionSyntheticBaselineDefinition {
	if d == nil {
		return nil
	}
	copy := *d
	copy.Mapping.CNAMEChain = slices.Clone(d.Mapping.CNAMEChain)
	return &copy
}

// Reconstruct COMPILER INTENT for common structural validation only. Actual
// effects retain the original compiler output issued from the original mapping
// before cancellation. No saved observation is ever used as execution input.
func syntheticBaselineDefinitionEffects(d *ExecutionSyntheticBaselineDefinition) (PolicyEffectPlan, error) {
	if d == nil || d.Schema != 1 || !validPlanID(d.PlanID) || !validPlanDigest(d.PlanDigest) || !validPlanDigest(d.DomainDigest) || d.NetworkIdentity.Validate() != nil {
		return PolicyEffectPlan{}, ErrExecutionJournal
	}
	r := d.Mapping
	if len(r.PublicationID) != 32 || strings.Trim(r.PublicationID, "0123456789abcdef") != "" || r.Authority.ControlEpoch == 0 || r.Authority.BindingRevision == 0 || !validPlanDigest(r.Authority.Exclusions.Digest) || r.ExpiresAt.IsZero() || len(r.CNAMEChain) > 128 {
		return PolicyEffectPlan{}, ErrExecutionJournal
	}
	for _, alias := range r.CNAMEChain {
		if alias == "" || len(alias) > 253 || strings.ToLower(alias) != alias || strings.ContainsAny(alias, "\x00\r\n\t /\\") {
			return PolicyEffectPlan{}, ErrExecutionJournal
		}
	}
	if r.PossiblyIssued {
		if r.LastPossiblyIssuedAt.IsZero() || !r.LastPossiblyIssuedAt.Before(r.ExpiresAt) || r.LastPossiblyIssuedTTLBound == 0 || r.LastPossiblyIssuedTTLBound > 0x7fffffff {
			return PolicyEffectPlan{}, ErrExecutionJournal
		}
	} else if !r.LastPossiblyIssuedAt.IsZero() || r.LastPossiblyIssuedTTLBound != 0 {
		return PolicyEffectPlan{}, ErrExecutionJournal
	}
	plan, err := syntheticBaselineTransitionEffects(r)
	if err != nil {
		return PolicyEffectPlan{}, err
	}
	if _, err := syntheticBaselineTupleFromPlan(plan); err != nil {
		return PolicyEffectPlan{}, err
	}
	return plan, nil
}

// CORE calls this after adding the typed field/kind to ExecutionResource. The
// phase/state is journal structure only, never a forwarding readiness signal.
func validateExecutionSyntheticBaselineResource(execution Execution, resource ExecutionResource, d *ExecutionSyntheticBaselineDefinition) error {
	if resource.Kind != "synthetic-baseline" || resource.NodeTransit != nil || resource.NFQWS != nil {
		return ErrExecutionJournal
	}
	parent := execution.PlanID
	if execution.ResourcePlanID != "" {
		parent = execution.ResourcePlanID
	}
	if d == nil || d.PlanID != parent || d.PlanDigest != execution.Digest {
		return ErrExecutionJournal
	}
	plan, err := syntheticBaselineDefinitionEffects(d)
	if err != nil || plan.Generation != resource.Generation {
		return ErrExecutionJournal
	}
	digest, err := PolicyEffectPlanDigest(plan)
	if err != nil || digest != resource.EffectsDigest {
		return ErrExecutionJournal
	}
	switch resource.Phase {
	case "planned", "baseline-prepared", "capture-ready", "transfer-intent", "transfer-ack", "closed":
		if resource.State != "prepared" {
			return ErrExecutionJournal
		}
	case "removed":
		if resource.State != "removed" {
			return ErrExecutionJournal
		}
	case "unused":
		if resource.State != "unused" {
			return ErrExecutionJournal
		}
	default:
		return ErrExecutionJournal
	}
	return nil
}

func (b *SyntheticDNSExecutionBinding) baselineResourceDefinition(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping) (*ExecutionSyntheticBaselineDefinition, error) {
	if err := b.Current(ctx); err != nil {
		return nil, err
	}
	plan, err := SyntheticBaselineTransitionEffects(ctx, b.transport, b.domain, mapping)
	if err != nil {
		return nil, err
	}
	r, err := mapping.Observation(ctx)
	if err != nil {
		return nil, err
	}
	d := &ExecutionSyntheticBaselineDefinition{Schema: 1, PlanID: b.plan.PlanID, PlanDigest: b.plan.Digest, DomainDigest: b.domain.Digest, Mapping: r, NetworkIdentity: b.scope.networkIdentity.value}
	compared, err := syntheticBaselineDefinitionEffects(d)
	if err != nil {
		return nil, err
	}
	actualDigest, err := PolicyEffectPlanDigest(plan)
	if err != nil {
		return nil, err
	}
	comparisonDigest, err := PolicyEffectPlanDigest(compared)
	if err != nil || comparisonDigest != actualDigest {
		return nil, ErrSyntheticBaselineTransition
	}
	if err := mapping.Current(ctx); err != nil {
		return nil, err
	}
	if err := b.Current(ctx); err != nil {
		return nil, err
	}
	return d, nil
}

// Only after original receipt authentication. This pure row conversion is not
// an allowance constructor; the common original consumer must retain its owner
// and receipt through the final complete inventory capture.
func syntheticBaselineReceiptRows(plan PolicyEffectPlan, states []string, borrowed bool) ([]BackendInventoryRow, []bool, error) {
	if _, err := syntheticBaselineTupleFromPlan(plan); err != nil || len(states) != len(plan.Effects) {
		return nil, nil, ErrPolicyAdditionReceipt
	}
	var rows []BackendInventoryRow
	var required []bool
	pending, planned := false, false
	for i, state := range states {
		switch state {
		case "added":
			if pending || planned {
				return nil, nil, ErrPolicyAdditionReceipt
			}
		case "intent":
			if pending || planned || !borrowed {
				return nil, nil, ErrPolicyAdditionReceipt
			}
			pending = true
		case "planned":
			if !borrowed {
				return nil, nil, ErrPolicyAdditionReceipt
			}
			planned = true
			continue
		default:
			return nil, nil, ErrPolicyAdditionReceipt
		}
		rows = append(rows, BackendInventoryRow{Family: 4, Table: "nat", Tokens: slices.Clone(plan.Effects[i].Add[2:])})
		required = append(required, state == "added")
	}
	return rows, required, nil
}
