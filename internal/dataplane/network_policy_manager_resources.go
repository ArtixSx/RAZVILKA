package dataplane

import (
	"errors"
	"slices"
	"strings"
)

const maxExecutionResources = 256

// ExecutionResource is typed retained intent inside the SAME execution
// journal. Its ID identifies a compiler-derived child root, never an arbitrary
// path. Neither serialized metadata nor "removed"/"unused" grants effects or
// cleanup: actual owner readback and the common receipt remain mandatory.
type ExecutionResource struct {
	ID            string           `json:"id"`
	Kind          string           `json:"kind"`
	State         string           `json:"state"` // prepared, removed, unused
	Generation    string           `json:"generation"`
	EffectsDigest string           `json:"effects_sha256"`
	NodeTransit   *NodeTransitSpec `json:"node_transit,omitempty"`
}

func cloneExecutionResources(resources []ExecutionResource) []ExecutionResource {
	result := slices.Clone(resources)
	for i := range result {
		if result[i].NodeTransit != nil {
			spec := *result[i].NodeTransit
			result[i].NodeTransit = &spec
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
		if (len(resource.ID) != len("nt-")+16 && len(resource.ID) != len("nt-")+32) || !strings.HasPrefix(resource.ID, "nt-") || strings.Trim(strings.TrimPrefix(resource.ID, "nt-"), "0123456789abcdef") != "" || seen[resource.ID] {
			return ErrExecutionJournal
		}
		seen[resource.ID] = true
		if resource.Kind != "node-transit" || resource.NodeTransit == nil || resource.NodeTransit.PlanID != planID || resource.NodeTransit.PlanDigest != execution.Digest {
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
