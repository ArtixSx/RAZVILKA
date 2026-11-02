package dataplane

import (
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Reader8 documentary links only. Each prior baseline still needs its SAME
// original closed DNS/kernel/receipt/file owners. These values cannot issue
// a successor, restore an owner after restart, or settle cached client data.
type ExecutionDomainDNSCoexistenceDefinition struct {
	Schema             int                                  `json:"schema"`
	NewPlanID          string                               `json:"new_plan_id"`
	NewPlanDigest      string                               `json:"new_plan_digest"`
	NewDomainDigest    string                               `json:"new_domain_digest"`
	NewDefinition      dnscontrol.SyntheticDNSDefinition    `json:"new_definition"`
	NewNetworkIdentity netidentity.Identity                 `json:"new_network_identity"`
	Prior              []ExecutionDomainDNSCoexistencePrior `json:"prior"`
}

type ExecutionDomainDNSCoexistencePrior struct {
	ExecutionPlanID string                               `json:"execution_plan_id"`
	Digest          string                               `json:"digest"`
	BaselineID      string                               `json:"baseline_id"`
	JournalSHA256   string                               `json:"journal_sha256"`
	Baseline        ExecutionSyntheticBaselineDefinition `json:"baseline"`
	Detached        ExecutionDomainDNSDetachedDefinition `json:"detached"`
}

func (d ExecutionDomainDNSCoexistenceDefinition) Clone() ExecutionDomainDNSCoexistenceDefinition {
	d.NewDefinition.ExactNames = slices.Clone(d.NewDefinition.ExactNames)
	if d.Prior == nil {
		return d
	}
	prior := make([]ExecutionDomainDNSCoexistencePrior, len(d.Prior))
	for i, row := range d.Prior {
		prior[i] = row
		prior[i].Baseline = *cloneExecutionSyntheticBaselineDefinition(&row.Baseline)
		prior[i].Detached = row.Detached.Clone()
	}
	d.Prior = prior
	return d
}

func (d ExecutionDomainDNSCoexistenceDefinition) validate(executionPlanID string, baseline *ExecutionSyntheticBaselineDefinition) error {
	if err := d.validateIntent(executionPlanID); err != nil {
		return err
	}
	if _, err := syntheticBaselineDefinitionEffects(baseline); err != nil {
		return ErrExecutionJournal
	}
	current := baseline.Mapping
	if baseline.PlanID != d.NewPlanID || baseline.PlanDigest != d.NewPlanDigest || baseline.DomainDigest != d.NewDomainDigest || baseline.NetworkIdentity != d.NewNetworkIdentity || current.Client != d.NewDefinition.Client || current.DeviceID != d.NewDefinition.DeviceID || current.MAC != d.NewDefinition.MAC || current.Ingress != d.NewDefinition.Ingress || current.QName != d.NewDefinition.ExactNames[0] {
		return ErrExecutionJournal
	}
	address := current.Synthetic.As4()
	index := int(address[2])*256 + int(address[3]) - 1
	if address[0] != 198 || address[1] != 18 || index < d.Prior[len(d.Prior)-1].Detached.LedgerCount || index >= 256 {
		return ErrExecutionJournal
	}
	for _, row := range d.Prior {
		if row.Baseline.Mapping.Synthetic == current.Synthetic {
			return ErrExecutionJournal
		}
	}
	return nil
}

// The first checking journal retains all prior footprints and frozen new
// intent. No fabricated mapping or pre-journal DNS Reserve is necessary.
func (d ExecutionDomainDNSCoexistenceDefinition) validateExecution(execution Execution) error {
	if d.NewPlanID != execution.ResourcePlanID || d.NewPlanDigest != execution.Digest {
		return ErrExecutionJournal
	}
	return d.validateIntent(execution.PlanID)
}

func (d ExecutionDomainDNSCoexistenceDefinition) validateIntent(executionPlanID string) error {
	if d.Schema != 1 || !domainTCPFiniteExecutionID(executionPlanID) || !validPlanID(d.NewPlanID) || !validPlanDigest(d.NewPlanDigest) || !validPlanDigest(d.NewDomainDigest) || d.NewNetworkIdentity.Validate() != nil || dnscontrol.ValidateSyntheticDNSDefinition(d.NewDefinition) != nil || len(d.NewDefinition.ExactNames) != 1 || len(d.Prior) < 1 || len(d.Prior) > 2 {
		return ErrExecutionJournal
	}
	seenPlans, seenIDs, seenAddresses, seenPrefixes := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	lastCount := 0
	for _, row := range d.Prior {
		id := strings.TrimPrefix(row.BaselineID, "sb-")
		if !domainTCPFiniteExecutionID(row.ExecutionPlanID) || row.ExecutionPlanID == executionPlanID || seenPlans[row.ExecutionPlanID] ||
			!validPlanDigest(row.Digest) || row.Digest != row.Baseline.PlanDigest || !validPlanDigest(row.JournalSHA256) ||
			!strings.HasPrefix(row.BaselineID, "sb-") || len(id) != 16 && len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" || seenIDs[row.BaselineID] ||
			row.Detached.validate(row.ExecutionPlanID, &row.Baseline) != nil || row.Detached.LedgerCount <= lastCount || row.Detached.LedgerCount >= 256 || seenPrefixes[row.Detached.LedgerPrefixSHA256] {
			return ErrExecutionJournal
		}
		old := row.Baseline.Mapping
		if row.Baseline.NetworkIdentity != d.NewNetworkIdentity || old.Client != d.NewDefinition.Client || old.MAC != d.NewDefinition.MAC || old.Ingress != d.NewDefinition.Ingress || old.DeviceID != d.NewDefinition.DeviceID || seenAddresses[old.Synthetic.String()] {
			return ErrExecutionJournal
		}
		seenPlans[row.ExecutionPlanID], seenIDs[row.BaselineID], seenAddresses[old.Synthetic.String()], seenPrefixes[row.Detached.LedgerPrefixSHA256] = true, true, true, true
		lastCount = row.Detached.LedgerCount
	}
	return nil
}

func domainTCPFiniteExecutionID(id string) bool {
	nonce := strings.TrimPrefix(id, "dp-check-")
	return strings.HasPrefix(id, "dp-check-") && len(nonce) == 32 && strings.Trim(nonce, "0123456789abcdef") == ""
}
