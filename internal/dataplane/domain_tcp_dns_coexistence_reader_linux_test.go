//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func domainCoexistenceReaderFixture(t *testing.T) (*Manager, Execution, context.Context) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "private-reader")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	d, id, current := domainDNSCoexistenceFixture(t)
	e := Execution{DomainDNSCoexistence: &d, PlanID: id, ResourcePlanID: current.PlanID, Digest: current.PlanDigest, State: "checking", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Steps: []ExecutionStep{{Adapter: "xray", Phase: "health", State: "running"}}}
	m := New(root)
	transaction := filepath.Join(root, "transactions", e.PlanID)
	if err := os.MkdirAll(transaction, 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.writeExecution(transaction, e); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	return m, e, ctx
}

// Actual original journal writer and protected whole-history decoder. These
// are documentary models; no original process/source/kernel grant is issued.
func TestDomainCoexistenceInitialCheckingRequiresReader8(t *testing.T) {
	m, e, ctx := domainCoexistenceReaderFixture(t)
	if len(e.Resources) != 0 {
		t.Fatal("initial test invented a mapping")
	}
	version, _, err := InspectRetainedExecutionReadVersion(ctx, m.StateRoot)
	if err != nil || version != 8 {
		t.Fatal("initial published marker lost minimum reader", version, err)
	}
	if m.CheckExecutionRecovery(ctx) == nil {
		t.Fatal("cold initial metadata adopted original standby pool")
	}
}

func TestDomainCoexistenceOlderLatestCannotHideArchivedReader8(t *testing.T) {
	m, e, ctx := domainCoexistenceReaderFixture(t)
	row := e.DomainDNSCoexistence.Prior[0]
	legacy := executionSyntheticResourceFixture(t)
	legacy.PlanID, legacy.ResourcePlanID, legacy.Digest, legacy.State = row.ExecutionPlanID, row.Baseline.PlanID, row.Digest, "resource-failed"
	legacy.Resources[0].SyntheticBaseline = cloneExecutionSyntheticBaselineDefinition(&row.Baseline)
	effects, err := syntheticBaselineDefinitionEffects(&row.Baseline)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Resources[0].Generation = effects.Generation
	legacy.Resources[0].EffectsDigest, err = PolicyEffectPlanDigest(effects)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Resources[0].ID = row.BaselineID
	detached := row.Detached.Clone()
	legacy.Resources[0].DomainDNSDetached = &detached
	legacy.Resources[0].Phase = "standby-detached"
	transaction := filepath.Join(m.StateRoot, "transactions", legacy.PlanID)
	if err := os.MkdirAll(transaction, 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.writeExecution(transaction, legacy); err != nil {
		t.Fatal(err)
	}
	version, _, err := InspectRetainedExecutionReadVersion(ctx, m.StateRoot)
	if err != nil || version != 8 {
		t.Fatal("reader7 latest hid original reader8 transaction", version, err)
	}
}

func TestDomainCoexistenceReaderRefusesUnknownInitialMarker(t *testing.T) {
	for _, change := range []string{"future", "unknown-field"} {
		t.Run(change, func(t *testing.T) {
			m, e, ctx := domainCoexistenceReaderFixture(t)
			raw, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			var marker map[string]json.RawMessage
			if err := json.Unmarshal(fields["domain_dns_coexistence"], &marker); err != nil {
				t.Fatal(err)
			}
			if change == "future" {
				marker["schema"] = json.RawMessage("2")
			} else {
				marker["future_owner"] = json.RawMessage("true")
			}
			fields["domain_dns_coexistence"], _ = json.Marshal(marker)
			raw, _ = json.Marshal(fields)
			// Deliberately invalid documentary bytes, never a production writer.
			for _, path := range []string{filepath.Join(m.StateRoot, "latest-execution.json"), filepath.Join(m.StateRoot, "transactions", e.PlanID, "execution.json")} {
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := InspectRetainedExecutionReadVersion(ctx, m.StateRoot); err == nil {
				t.Fatal("unknown initial coexistence marker accepted", change)
			}
		})
	}
}
