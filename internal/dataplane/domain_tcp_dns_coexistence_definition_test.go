package dataplane

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// Structural/wire data only: these fixtures contain no original FD or owner.
// Literal documentary fixtures deliberately bypass the SAME-successor issuer
// entry. Real writer provenance is exercised by the separate native workflow.
func writeDomainCoexistenceDocumentFixture(t *testing.T, m *Manager, root string, e Execution) {
	t.Helper()
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if !executionHasNetworkIdentity(e) {
		t.Fatal("initial marker lost compact typed identity format")
	}
	for _, path := range []string{filepath.Join(root, "execution.json"), filepath.Join(m.StateRoot, "latest-execution.json")} {
		if err := writeDataplaneJournal(path, data); err != nil {
			t.Fatal(err)
		}
	}
}

func domainDNSCoexistenceFixture(t *testing.T) (ExecutionDomainDNSCoexistenceDefinition, string, *ExecutionSyntheticBaselineDefinition) {
	t.Helper()
	e := executionSyntheticResourceFixture(t)
	old := cloneExecutionSyntheticBaselineDefinition(e.Resources[0].SyntheticBaseline)
	priorID := "dp-check-" + strings.Repeat("a", 32)
	closed := old.Mapping
	closed.PossiblyIssued = true
	closed.LastPossiblyIssuedAt = closed.ExpiresAt.Add(-30 * time.Second)
	closed.LastPossiblyIssuedTTLBound = 30
	d := ExecutionDomainDNSCoexistenceDefinition{Schema: 1, Prior: []ExecutionDomainDNSCoexistencePrior{{
		ExecutionPlanID: priorID, Digest: old.PlanDigest, BaselineID: "sb-" + strings.Repeat("a", 32), JournalSHA256: strings.Repeat("c", 64), Baseline: *old,
		Detached: ExecutionDomainDNSDetachedDefinition{Schema: 1, OwnerName: "retired-" + priorID + "-owner.json", OwnerSHA256: strings.Repeat("a", 64), LedgerPrefixSHA256: strings.Repeat("b", 64), LedgerCount: 1, ClosedMapping: closed},
	}}}
	current := cloneExecutionSyntheticBaselineDefinition(old)
	current.Mapping.Synthetic = netip.MustParseAddr("198.18.0.2")
	current.Mapping.PublicationID = strings.Repeat("d", 32)
	d.NewPlanID, d.NewPlanDigest, d.NewDomainDigest, d.NewNetworkIdentity = current.PlanID, current.PlanDigest, current.DomainDigest, current.NetworkIdentity
	d.NewDefinition = dnscontrol.SyntheticDNSDefinition{Client: current.Mapping.Client, DeviceID: current.Mapping.DeviceID, MAC: current.Mapping.MAC, Ingress: current.Mapping.Ingress, ExactNames: []string{current.Mapping.QName}}
	return d, "dp-check-" + strings.Repeat("b", 32), current
}

func TestDomainCoexistenceColdTerminalStillFencesRetainedPriorFootprints(t *testing.T) {
	d, id, current := domainDNSCoexistenceFixture(t)
	root := filepath.Join(t.TempDir(), "private-cold")
	transaction := filepath.Join(root, "transactions", id)
	if err := os.MkdirAll(transaction, 0700); err != nil {
		t.Fatal(err)
	}
	finished := time.Now().UTC().Format(time.RFC3339Nano)
	e := Execution{DomainDNSCoexistence: &d, PlanID: id, ResourcePlanID: current.PlanID, Digest: current.PlanDigest, State: "temporary-complete", StartedAt: finished, FinishedAt: finished}
	m := New(root)
	writeDomainCoexistenceDocumentFixture(t, m, transaction, e)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if m.CheckExecutionRecovery(ctx) == nil {
		t.Fatal("terminal new attempt hid still-retained prior baselines without original pool")
	}
}

func TestDomainDNSCoexistenceEveryNewBaselinePhaseRetainsPriorHistory(t *testing.T) {
	d, id, current := domainDNSCoexistenceFixture(t)
	effects, err := syntheticBaselineDefinitionEffects(current)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := PolicyEffectPlanDigest(effects)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"planned", "baseline-prepared", "capture-ready", "transfer-intent", "transfer-ack", "closed", "standby-retained", "standby-detached", "removed", "unused"} {
		t.Run(phase, func(t *testing.T) {
			marker := d.Clone()
			row := ExecutionResource{ID: "sb-" + strings.Repeat("f", 32), Kind: "synthetic-baseline", State: "prepared", Phase: phase, Generation: effects.Generation, EffectsDigest: digest, SyntheticBaseline: cloneExecutionSyntheticBaselineDefinition(current), DomainDNSCoexistence: &marker}
			switch phase {
			case "removed":
				row.State = "removed"
			case "unused":
				row.State = "unused"
			case "standby-detached":
				mapping := current.Mapping
				mapping.PossiblyIssued = true
				mapping.LastPossiblyIssuedAt = mapping.ExpiresAt.Add(-time.Second)
				mapping.LastPossiblyIssuedTTLBound = 1
				row.DomainDNSDetached = &ExecutionDomainDNSDetachedDefinition{Schema: 1, OwnerName: "retired-" + id + "-owner.json", OwnerSHA256: strings.Repeat("e", 64), LedgerPrefixSHA256: strings.Repeat("f", 64), LedgerCount: 2, ClosedMapping: mapping}
			}
			e := Execution{PlanID: id, ResourcePlanID: current.PlanID, Digest: current.PlanDigest, State: "checking", DomainDNSCoexistence: &marker, Resources: []ExecutionResource{row}}
			if err := validateExecutionResources(e, false); err != nil {
				t.Fatal("prior history erased/refused by new phase", phase, err)
			}
			raw, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			var wire Execution
			if err := json.Unmarshal(raw, &wire); err != nil || validateExecutionResources(wire, false) != nil || wire.DomainDNSCoexistence == nil || len(wire.DomainDNSCoexistence.Prior) != 1 {
				t.Fatal("wire lost old footprint", err)
			}
		})
	}
}

func TestDomainDNSCoexistenceDefinitionStrictWireAndClone(t *testing.T) {
	d, id, current := domainDNSCoexistenceFixture(t)
	if err := d.validate(id, current); err != nil {
		t.Fatal(err)
	}
	for _, chain := range [][]string{nil, {}, {"alias.example.com"}} {
		copy := d.Clone()
		copy.Prior[0].Baseline.Mapping.CNAMEChain = chain
		copy.Prior[0].Detached.ClosedMapping.CNAMEChain = chain
		raw, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		var wire ExecutionDomainDNSCoexistenceDefinition
		if err := json.Unmarshal(raw, &wire); err != nil || wire.validate(id, current) != nil {
			t.Fatal("wire comparison changed", err)
		}
	}
	copy := d.Clone()
	copy.NewDefinition.ExactNames[0] = "changed.example.com"
	if d.NewDefinition.ExactNames[0] == "changed.example.com" {
		t.Fatal("clone aliases original frozen new intent")
	}
	copy.Prior[0].Baseline.Mapping.CNAMEChain[0] = "changed.example.com"
	copy.Prior[0].Detached.ClosedMapping.CNAMEChain[0] = "changed.example.com"
	if d.Prior[0].Baseline.Mapping.CNAMEChain[0] == "changed.example.com" || d.Prior[0].Detached.ClosedMapping.CNAMEChain[0] == "changed.example.com" {
		t.Fatal("clone aliases its immutable predecessor")
	}
}

func TestDomainDNSCoexistenceInitialCheckingNeedsNoFabricatedMapping(t *testing.T) {
	d, id, current := domainDNSCoexistenceFixture(t)
	e := Execution{PlanID: id, ResourcePlanID: current.PlanID, Digest: current.PlanDigest, State: "checking"}
	if err := d.validateExecution(e); err != nil || len(e.Resources) != 0 {
		t.Fatal("first global marker needs a fabricated mapping", err)
	}
	for _, change := range []string{"plan", "digest", "foreign-intent", "name", "network"} {
		copy, execution := d.Clone(), e
		switch change {
		case "plan":
			execution.ResourcePlanID = "dp-" + strings.Repeat("f", 16)
		case "digest":
			execution.Digest = strings.Repeat("f", 64)
		case "foreign-intent":
			copy.NewPlanID = "dp-" + strings.Repeat("f", 16)
		case "name":
			copy.NewDefinition.ExactNames = nil
		case "network":
			copy.NewNetworkIdentity.BootID = "22222222-2222-4333-8444-555555555555"
		}
		if copy.validateExecution(execution) == nil {
			t.Fatal("changed initial global intent accepted", change)
		}
	}
}

func TestDomainDNSCoexistenceDefinitionRejectsChangedLinks(t *testing.T) {
	for _, change := range []string{"future", "empty", "overflow", "same-execution", "bad-journal", "bad-resource", "duplicate", "alias-reuse", "physical-rebind", "network-rebind", "prefix-full", "unissued"} {
		t.Run(change, func(t *testing.T) {
			d, id, current := domainDNSCoexistenceFixture(t)
			switch change {
			case "future":
				d.Schema++
			case "empty":
				d.Prior = nil
			case "overflow":
				d.Prior = append(d.Prior, d.Prior[0], d.Prior[0])
			case "same-execution":
				d.Prior[0].ExecutionPlanID = id
			case "bad-journal":
				d.Prior[0].JournalSHA256 = "unknown"
			case "bad-resource":
				d.Prior[0].BaselineID = "nt-" + strings.Repeat("a", 32)
			case "duplicate":
				d.Prior = append(d.Prior, d.Prior[0])
			case "alias-reuse":
				current.Mapping.Synthetic = d.Prior[0].Baseline.Mapping.Synthetic
			case "physical-rebind":
				current.Mapping.MAC = "02:00:00:00:00:ff"
			case "network-rebind":
				current.NetworkIdentity.BootID = "11111111-2222-4333-8444-555555555555"
			case "prefix-full":
				d.Prior[0].Detached.LedgerCount = 256
			case "unissued":
				d.Prior[0].Detached.ClosedMapping.PossiblyIssued = false
			}
			if d.validate(id, current) == nil {
				t.Fatal("changed coexistence comparison accepted", change)
			}
		})
	}
}

func TestDomainDNSCoexistenceDefinitionKeepsTwoOrderedPrefixes(t *testing.T) {
	d, id, current := domainDNSCoexistenceFixture(t)
	second := d.Clone().Prior[0]
	second.ExecutionPlanID = "dp-check-" + strings.Repeat("c", 32)
	second.BaselineID = "sb-" + strings.Repeat("b", 32)
	second.JournalSHA256 = strings.Repeat("e", 64)
	second.Baseline.Mapping.Synthetic = netip.MustParseAddr("198.18.0.2")
	second.Baseline.Mapping.PublicationID = strings.Repeat("e", 32)
	second.Detached.OwnerName = "retired-" + second.ExecutionPlanID + "-owner.json"
	second.Detached.LedgerPrefixSHA256 = strings.Repeat("f", 64)
	second.Detached.LedgerCount = 2
	second.Detached.ClosedMapping.Synthetic = second.Baseline.Mapping.Synthetic
	second.Detached.ClosedMapping.PublicationID = second.Baseline.Mapping.PublicationID
	d.Prior = append(d.Prior, second)
	current.Mapping.Synthetic = netip.MustParseAddr("198.18.0.3")
	if err := d.validate(id, current); err != nil {
		t.Fatal("two original typed prefix comparisons refused", err)
	}
	for _, change := range []string{"order", "shrinking", "same-prefix"} {
		copy := d.Clone()
		switch change {
		case "order":
			copy.Prior[0], copy.Prior[1] = copy.Prior[1], copy.Prior[0]
		case "shrinking":
			copy.Prior[1].Detached.LedgerCount = 1
		case "same-prefix":
			copy.Prior[1].Detached.LedgerPrefixSHA256 = copy.Prior[0].Detached.LedgerPrefixSHA256
		}
		if copy.validate(id, current) == nil {
			t.Fatal("immutable prefix ancestry changed", change)
		}
	}
}
