package dataplane

import (
	"strings"
	"testing"
	"time"
)

// Wire/comparison model only; it has no original source, writer or admission.
func TestDomainDNSDetachedDefinitionBindsOriginalClosedComparison(t *testing.T) {
	e := executionSyntheticResourceFixture(t)
	baseline := e.Resources[0].SyntheticBaseline
	d := ExecutionDomainDNSDetachedDefinition{Schema: 1, OwnerName: "retired-" + e.PlanID + "-owner.json", OwnerSHA256: strings.Repeat("a", 64), LedgerPrefixSHA256: strings.Repeat("b", 64), LedgerCount: 1, ClosedMapping: baseline.Mapping}
	d.ClosedMapping.PossiblyIssued = true
	d.ClosedMapping.LastPossiblyIssuedAt = baseline.Mapping.ExpiresAt.Add(-30 * time.Second)
	d.ClosedMapping.LastPossiblyIssuedTTLBound = 30
	if err := d.validate(e.PlanID, baseline); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"owner", "digest", "count", "unissued", "mapping", "ttl", "future"} {
		t.Run(change, func(t *testing.T) {
			copy := d.Clone()
			switch change {
			case "owner":
				copy.OwnerName = "retired-foreign-owner.json"
			case "digest":
				copy.LedgerPrefixSHA256 = strings.Repeat("0", 63)
			case "count":
				copy.LedgerCount = 0
			case "unissued":
				copy.ClosedMapping.PossiblyIssued = false
			case "mapping":
				copy.ClosedMapping.CNAMEChain[0] = "different.example.com"
			case "ttl":
				copy.ClosedMapping.LastPossiblyIssuedTTLBound++
			case "future":
				copy.Schema++
			}
			if copy.validate(e.PlanID, baseline) == nil {
				t.Fatal("changed retained comparison accepted")
			}
		})
	}
	if d.ClosedMapping.CNAMEChain[0] != baseline.Mapping.CNAMEChain[0] || d.validate(e.PlanID, baseline) != nil {
		t.Fatal("detached clone changed its original")
	}
}
