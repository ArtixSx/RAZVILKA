package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func networkPolicyTransferJournalFixture(t *testing.T, phase string) Execution {
	t.Helper()
	e := executionNFQWSResourceFixture(t, phase)
	identity, _ := networkPolicyIdentityFixture()
	bindNetworkPolicyTypedExecutionFixture(t, &e, identity.value)
	d, r := e.Resources[0].NFQWS, &e.Resources[0]
	d.Mode = nfqws2ActiveProcessMode
	if phase == "transfer-ack" || phase == "closed" || phase == "removed" {
		p, err := CompileNFQWSScopedPlan(d.Plan, d.Spec)
		if err != nil {
			t.Fatal(err)
		}
		model := nfqwsScopedModel{p: p, running: true}
		proof := model.proof(false)
		d.Observation = &NFQWSActiveObservation{NetworkIdentity: identity.value, Receipt: proof.Receipt, Child: proof.Child,
			Binding: NFQWSExecutionBinding{ExecutionID: e.PlanID, PlanID: d.Plan.PlanID, PlanDigest: d.Plan.Digest, ResourceID: r.ID,
				ResourceGeneration: r.Generation, EffectsDigest: r.EffectsDigest, SessionID: d.Spec.SessionID, CommandSHA256: d.Spec.CommandSHA256}}
	}
	return e
}

func TestNetworkPolicyManagerTransferRecordsNeverPublishOrAdoptActive(t *testing.T) {
	for _, phase := range []string{"transfer-intent", "transfer-ack", "closed"} {
		t.Run(phase, func(t *testing.T) {
			e := networkPolicyTransferJournalFixture(t, phase)
			if err := validateExecutionResources(e, false); err != nil {
				t.Fatal("valid nonterminal reference refused", err)
			}
			if err := validateExecutionResources(e, true); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("provisional transfer became terminal", err)
			}
			m := New(privateScopedXrayFixtureDir(t))
			root := filepath.Join(m.StateRoot, "transactions", e.PlanID)
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			if err := m.writeExecution(root, e); err != nil {
				t.Fatal(err)
			}
			if err := New(m.StateRoot).CheckExecutionRecovery(context.Background()); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("restart adopted pending transfer", err)
			}
			e.State, e.FinishedAt = "committing", e.StartedAt
			if err := m.writeExecution(root, e); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("writer published nonterminal transfer", err)
			}
			// Even forged matching metadata + committed plan cannot invoke the
			// old metadata-only finishCommit recovery on an actual transfer.
			e.Steps = []ExecutionStep{{Adapter: "nfqws2", Phase: "health", State: "passed", FinishedAt: e.FinishedAt}}
			data, _ := json.Marshal(e)
			for _, path := range []string{filepath.Join(root, "execution.json"), filepath.Join(m.StateRoot, "latest-execution.json")} {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			plan := e.Resources[0].NFQWS.Plan
			plan.State = "committed"
			if err := m.recordLocked(plan); err != nil {
				t.Fatal(err)
			}
			if settled, err := m.settleCommittedPublication(); settled || err != nil {
				t.Fatal("committed snapshot adopted provisional owner", settled, err)
			}
			after, err := os.ReadFile(filepath.Join(root, "execution.json"))
			if err != nil || string(after) != string(data) {
				t.Fatal("read-only refusal repaired journal", err)
			}
		})
	}
}

func TestNetworkPolicyManagerTransferDefinitionRejectsEveryChangedBinding(t *testing.T) {
	for name, change := range map[string]func(*Execution){
		"missing mode":          func(e *Execution) { e.Resources[0].NFQWS.Mode = "" },
		"unknown mode":          func(e *Execution) { e.Resources[0].NFQWS.Mode = "active" },
		"missing observation":   func(e *Execution) { e.Resources[0].NFQWS.Observation = nil },
		"premature observation": func(e *Execution) { e.Resources[0].Phase = "transfer-intent" },
		"temporary attempt":     func(e *Execution) { e.ResourcePlanID = e.PlanID; e.PlanID = "dp-check-0123456789abcdef" },
		"execution":             func(e *Execution) { e.Resources[0].NFQWS.Observation.Binding.ExecutionID = "dp-other" },
		"plan":                  func(e *Execution) { e.Resources[0].NFQWS.Observation.Binding.PlanID = "dp-other" },
		"digest":                func(e *Execution) { e.Resources[0].NFQWS.Observation.Binding.PlanDigest = "wrong" },
		"resource":              func(e *Execution) { e.Resources[0].NFQWS.Observation.Binding.ResourceID = "nq-wrong" },
		"generation":            func(e *Execution) { e.Resources[0].NFQWS.Observation.Binding.ResourceGeneration = "wrong" },
		"effects":               func(e *Execution) { e.Resources[0].NFQWS.Observation.Binding.EffectsDigest = "wrong" },
		"session":               func(e *Execution) { e.Resources[0].NFQWS.Observation.Binding.SessionID = "wrong" },
		"command":               func(e *Execution) { e.Resources[0].NFQWS.Observation.Binding.CommandSHA256 = "wrong" },
		"identity": func(e *Execution) {
			e.Resources[0].NFQWS.Observation.NetworkIdentity.Kind = netidentity.ReviewedSingleInitNet
		},
		"child birth":  func(e *Execution) { e.Resources[0].NFQWS.Observation.Child.Start = "0" },
		"helper birth": func(e *Execution) { e.Resources[0].NFQWS.Observation.Receipt.Start = "0" },
		"inactive":     func(e *Execution) { e.Resources[0].NFQWS.Observation.Receipt.State = "reaped" },
		"active state": func(e *Execution) { e.Resources[0].State = "active"; e.Resources[0].Phase = "active" },
	} {
		t.Run(name, func(t *testing.T) {
			e := networkPolicyTransferJournalFixture(t, "transfer-ack")
			change(&e)
			if err := validateExecutionResources(e, false); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("changed transfer reference passed", err)
			}
		})
	}
	original := networkPolicyTransferJournalFixture(t, "transfer-ack")
	copy := cloneExecutionResources(original.Resources)
	copy[0].NFQWS.Observation.Child.Start = "0"
	if err := validateExecutionResources(original, false); err != nil {
		t.Fatal("observation clone aliased original", err)
	}
}
