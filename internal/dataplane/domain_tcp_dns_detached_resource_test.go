package dataplane

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func detachedDNSExecutionModel(t *testing.T) Execution {
	t.Helper()
	e := executionSyntheticResourceFixture(t)
	r := &e.Resources[0]
	d := &ExecutionDomainDNSDetachedDefinition{Schema: 1, OwnerName: "retired-" + e.PlanID + "-owner.json", OwnerSHA256: strings.Repeat("a", 64), LedgerPrefixSHA256: strings.Repeat("b", 64), LedgerCount: 1, ClosedMapping: r.SyntheticBaseline.Mapping}
	d.ClosedMapping.PossiblyIssued = true
	d.ClosedMapping.LastPossiblyIssuedAt = d.ClosedMapping.ExpiresAt.Add(-30 * time.Second)
	d.ClosedMapping.LastPossiblyIssuedTTLBound = 30
	r.DomainDNSDetached = d
	r.State, r.Phase = "prepared", "standby-detached"
	return e
}

func TestDomainDNSDetachedWirePreservesPendingAndTerminalHistory(t *testing.T) {
	e := detachedDNSExecutionModel(t)
	before := e.Resources[0].EffectsDigest
	for _, phase := range []string{"standby-detached", "removed"} {
		e.Resources[0].Phase = phase
		if phase == "removed" {
			e.Resources[0].State = "removed"
		}
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Execution
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if err := validateExecutionResources(decoded, false); err != nil {
			t.Fatal("valid wire refused", phase, err)
		}
		if err := validateExecutionResources(decoded, true); (err == nil) != (phase == "removed") {
			t.Fatal("detached baseline declared terminal", phase, err)
		}
		if decoded.Resources[0].EffectsDigest != before {
			t.Fatal("detachment changed frozen effects")
		}
	}
	cloned := cloneExecutionResources(e.Resources)
	cloned[0].DomainDNSDetached.ClosedMapping.CNAMEChain[0] = "foreign.example"
	if e.Resources[0].DomainDNSDetached.ClosedMapping.CNAMEChain[0] == "foreign.example" {
		t.Fatal("clone shares immutable prefix comparison")
	}
}

func TestDomainDNSDetachedWireRefusesMissingMixedAndWidenedHistory(t *testing.T) {
	for _, mode := range []string{"missing", "ordinary-phase", "unused", "other-kind", "larger-pool", "changed-prefix-mapping"} {
		t.Run(mode, func(t *testing.T) {
			e := detachedDNSExecutionModel(t)
			r := &e.Resources[0]
			switch mode {
			case "missing":
				r.DomainDNSDetached = nil
			case "ordinary-phase":
				r.Phase = "standby-retained"
			case "unused":
				r.Phase, r.State = "unused", "unused"
			case "other-kind":
				r.Kind = "node-transit"
			case "larger-pool":
				r.DomainDNSDetached.LedgerCount = 257
			case "changed-prefix-mapping":
				r.DomainDNSDetached.ClosedMapping.RealIPv4 = r.DomainDNSDetached.ClosedMapping.Synthetic
			}
			if err := validateExecutionResources(e, false); err == nil {
				t.Fatal("changed wire accepted")
			}
		})
	}
}
