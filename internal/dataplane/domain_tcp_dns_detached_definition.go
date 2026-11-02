package dataplane

import (
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// ExecutionDomainDNSDetachedDefinition is reader7 comparison data for a
// joined DNS owner whose restorative baseline remains owned. It grants no
// publication, native process, alias reuse, cleanup or client-cache settlement.
// The original producer and shared reader admission are wired separately;
// no current writer emits this definition.
type ExecutionDomainDNSDetachedDefinition struct {
	Schema             int                                       `json:"schema"`
	OwnerName          string                                    `json:"owner_name"`
	OwnerSHA256        string                                    `json:"owner_sha256"`
	LedgerPrefixSHA256 string                                    `json:"ledger_prefix_sha256"`
	LedgerCount        int                                       `json:"ledger_count"`
	ClosedMapping      dnscontrol.SyntheticDNSMappingObservation `json:"closed_mapping"`
}

func (d ExecutionDomainDNSDetachedDefinition) Clone() ExecutionDomainDNSDetachedDefinition {
	d.ClosedMapping.CNAMEChain = slices.Clone(d.ClosedMapping.CNAMEChain)
	return d
}

// Pure retained-wire validation only. A hash or valid DTO cannot reconstruct
// the original closed source, its writer FD, COMMON receipt or live baseline.
func (d ExecutionDomainDNSDetachedDefinition) validate(executionPlanID string, baseline *ExecutionSyntheticBaselineDefinition) error {
	finiteID := strings.TrimPrefix(executionPlanID, "dp-check-")
	finite := strings.HasPrefix(executionPlanID, "dp-check-") && len(finiteID) == 32 && strings.Trim(finiteID, "0123456789abcdef") == ""
	if d.Schema != 1 || !validPlanID(executionPlanID) && !finite || d.OwnerName != "retired-"+executionPlanID+"-owner.json" || !validPlanDigest(d.OwnerSHA256) || !validPlanDigest(d.LedgerPrefixSHA256) || d.LedgerCount < 1 || d.LedgerCount > 256 {
		return ErrExecutionJournal
	}
	if _, err := syntheticBaselineDefinitionEffects(baseline); err != nil {
		return ErrExecutionJournal
	}
	closed, original := d.ClosedMapping, baseline.Mapping
	if !closed.PossiblyIssued || closed.LastPossiblyIssuedAt.IsZero() || !closed.LastPossiblyIssuedAt.Before(closed.ExpiresAt) || closed.LastPossiblyIssuedTTLBound == 0 || closed.LastPossiblyIssuedTTLBound > 0x7fffffff {
		return ErrExecutionJournal
	}
	remaining := closed.ExpiresAt.Sub(closed.LastPossiblyIssuedAt)
	if remaining <= 0 || remaining > time.Duration(0x7fffffff)*time.Second || uint32((remaining+time.Second-1)/time.Second) != closed.LastPossiblyIssuedTTLBound {
		return ErrExecutionJournal
	}
	closed.PossiblyIssued, original.PossiblyIssued = false, false
	closed.LastPossiblyIssuedAt, original.LastPossiblyIssuedAt = time.Time{}, time.Time{}
	closed.LastPossiblyIssuedTTLBound, original.LastPossiblyIssuedTTLBound = 0, 0
	if !reflect.DeepEqual(closed, original) {
		return ErrExecutionJournal
	}
	address := closed.Synthetic.As4()
	index := int(address[2])*256 + int(address[3]) - 1
	if address[0] != 198 || address[1] != 18 || index < 0 || index >= d.LedgerCount {
		return ErrExecutionJournal
	}
	return nil
}
