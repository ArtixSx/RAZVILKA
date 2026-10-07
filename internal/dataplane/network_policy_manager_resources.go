package dataplane

import (
	"errors"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

const maxExecutionResources = 256

// ExecutionResource is typed retained intent inside the SAME execution
// journal. Its ID identifies a compiler-derived child root, never an arbitrary
// path. Neither serialized metadata nor "removed"/"unused" grants effects or
// cleanup: actual owner readback and the common receipt remain mandatory.
type ExecutionResource struct {
	ID            string                    `json:"id"`
	Kind          string                    `json:"kind"`
	State         string                    `json:"state"` // prepared, removed, unused
	Generation    string                    `json:"generation"`
	EffectsDigest string                    `json:"effects_sha256"`
	NodeTransit   *NodeTransitSpec          `json:"node_transit,omitempty"`
	NFQWS         *ExecutionNFQWSDefinition `json:"nfqws,omitempty"`
	Phase         string                    `json:"phase,omitempty"`
}

// ExecutionNFQWSDefinition retains full typed compiler input, never argv or
// executable paths. Reconstructing it checks intent only, not launch authority.
type ExecutionNFQWSDefinition struct {
	Plan            Plan                    `json:"plan"`
	Spec            NFQWSScopedSpec         `json:"spec"`
	NetworkIdentity *netidentity.Identity   `json:"network_identity,omitempty"`
	Mode            string                  `json:"mode,omitempty"`
	Observation     *NFQWSActiveObservation `json:"observation,omitempty"`
}

func cloneExecutionResources(resources []ExecutionResource) []ExecutionResource {
	result := slices.Clone(resources)
	for i := range result {
		if result[i].NodeTransit != nil {
			spec := *result[i].NodeTransit
			result[i].NodeTransit = &spec
		}
		if result[i].NFQWS != nil {
			definition := *result[i].NFQWS
			definition.Plan = cloneExecutionResourcePlan(definition.Plan)
			definition.Spec = definition.Spec.Clone()
			if definition.NetworkIdentity != nil {
				identity := *definition.NetworkIdentity
				definition.NetworkIdentity = &identity
			}
			if definition.Observation != nil {
				observation := *definition.Observation
				definition.Observation = &observation
			}
			result[i].NFQWS = &definition
		}
	}
	return result
}

func validateExecutionResources(execution Execution, terminal bool) error {
	if len(execution.Resources) > maxExecutionResources {
		return ErrExecutionJournal
	}
	planID := execution.PlanID
	if execution.ResourcePlanID != "" {
		if !validPlanID(execution.ResourcePlanID) || !validPlanDigest(execution.Digest) || execution.State == "committed" || execution.State == "committing" {
			return ErrExecutionJournal
		}
		planID = execution.ResourcePlanID
	}
	if execution.State == "temporary-complete" && execution.ResourcePlanID == "" {
		return ErrExecutionJournal
	}
	seen := map[string]bool{}
	for _, resource := range execution.Resources {
		prefix := "nt-"
		if resource.Kind == "nfqws-scoped" {
			prefix = "nq-"
		}
		if (len(resource.ID) != len(prefix)+16 && len(resource.ID) != len(prefix)+32) || !strings.HasPrefix(resource.ID, prefix) || strings.Trim(strings.TrimPrefix(resource.ID, prefix), "0123456789abcdef") != "" || seen[resource.ID] {
			return ErrExecutionJournal
		}
		seen[resource.ID] = true
		switch resource.Kind {
		case "node-transit":
			if resource.NodeTransit == nil || resource.NFQWS != nil || resource.Phase != "" || resource.NodeTransit.PlanID != planID || resource.NodeTransit.PlanDigest != execution.Digest {
				return ErrExecutionJournal
			}
			plan, err := CompileNodeTransit(*resource.NodeTransit)
			if err != nil || plan.Generation != resource.Generation {
				return errors.Join(ErrExecutionJournal, err)
			}
			digest, err := PolicyEffectPlanDigest(plan)
			if err != nil || digest != resource.EffectsDigest {
				return errors.Join(ErrExecutionJournal, err)
			}
		case "nfqws-scoped":
			if resource.NFQWS == nil || resource.NodeTransit != nil || resource.NFQWS.Plan.PlanID != planID || resource.NFQWS.Plan.Digest != execution.Digest {
				return ErrExecutionJournal
			}
			if resource.NFQWS.NetworkIdentity != nil {
				if err := nfqwsExecutionNetworkMatches(*resource.NFQWS.NetworkIdentity, resource.NFQWS.Spec); err != nil {
					return errors.Join(ErrExecutionJournal, err)
				}
			} else if resource.NFQWS.Spec.NetworkIdentity != nil {
				return ErrExecutionJournal
			}
			plan, err := CompileNFQWSScopedPlan(resource.NFQWS.Plan, resource.NFQWS.Spec)
			if err != nil || plan.Resources().Generation != resource.Generation || plan.Digest() != resource.EffectsDigest {
				return errors.Join(ErrExecutionJournal, err)
			}
			if err := validateExecutionNFQWSMode(execution, resource, plan); err != nil {
				return err
			}
			switch resource.Phase {
			case "planned", "process-pending", "capture-ready", "transfer-intent", "transfer-ack", "closed":
				if resource.State != "prepared" {
					return ErrExecutionJournal
				}
			case "removed":
				if resource.State != "removed" {
					return ErrExecutionJournal
				}
			default:
				return ErrExecutionJournal
			}
		default:
			return ErrExecutionJournal
		}
		switch resource.State {
		case "prepared":
			if terminal {
				return errors.Join(ErrExecutionJournal, ErrPolicyAdditionUnknown)
			}
		case "removed", "unused":
		default:
			return ErrExecutionJournal
		}
	}
	return nil
}
