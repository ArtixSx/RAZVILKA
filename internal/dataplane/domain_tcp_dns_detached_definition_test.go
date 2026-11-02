package dataplane

import (
	"bytes"
	"encoding/json"
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
	// A JSON round trip preserves the wire's null/[] distinction in both
	// compared observations; it cannot silently rebind an original prefix.
	for _, chain := range [][]string{nil, {}, {"alias.example.com"}} {
		wireModel := struct {
			Baseline ExecutionSyntheticBaselineDefinition
			Detached ExecutionDomainDNSDetachedDefinition
		}{Baseline: *baseline, Detached: d.Clone()}
		wireModel.Baseline.Mapping.CNAMEChain = chain
		wireModel.Detached.ClosedMapping.CNAMEChain = chain
		wire, err := json.Marshal(wireModel)
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(wire))
		decoder.DisallowUnknownFields()
		var restored struct {
			Baseline ExecutionSyntheticBaselineDefinition
			Detached ExecutionDomainDNSDetachedDefinition
		}
		if err := decoder.Decode(&restored); err != nil {
			t.Fatal(err)
		}
		if err := restored.Detached.validate(e.PlanID, &restored.Baseline); err != nil {
			t.Fatal("typed wire roundtrip changed comparison", err)
		}
	}
	for _, change := range []string{"owner", "digest", "count", "count-overflow", "unissued", "mapping", "ttl", "future"} {
		t.Run(change, func(t *testing.T) {
			copy := d.Clone()
			switch change {
			case "owner":
				copy.OwnerName = "retired-foreign-owner.json"
			case "digest":
				copy.LedgerPrefixSHA256 = strings.Repeat("0", 63)
			case "count":
				copy.LedgerCount = 0
			case "count-overflow":
				copy.LedgerCount = 257
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
