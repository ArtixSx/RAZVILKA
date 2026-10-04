package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func networkPolicyResourceFixture(t *testing.T, state string) Execution {
	t.Helper()
	spec := nodeTransitFixtureSpec()
	plan, err := CompileNodeTransit(spec)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := PolicyEffectPlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	return Execution{PlanID: spec.PlanID, Digest: spec.PlanDigest, State: "committed", StartedAt: time.Unix(100, 0).UTC().Format(time.RFC3339Nano), FinishedAt: time.Unix(101, 0).UTC().Format(time.RFC3339Nano),
		Resources: []ExecutionResource{{ID: "nt-0123456789abcdef", Kind: "node-transit", State: state, Generation: plan.Generation, EffectsDigest: digest, NodeTransit: &spec}}}
}

func TestNetworkPolicyManagerResourceRestartRejectsUnsettledTerminal(t *testing.T) {
	for _, state := range []string{"prepared", "removed", "unused"} {
		t.Run(state, func(t *testing.T) {
			m := New(t.TempDir())
			execution := networkPolicyResourceFixture(t, state)
			root := filepath.Join(m.StateRoot, "transactions", execution.PlanID)
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(execution)
			// Simulate persisted terminal bytes, bypassing the writer's guard.
			for _, path := range []string{filepath.Join(root, "execution.json"), filepath.Join(m.StateRoot, "latest-execution.json")} {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := New(m.StateRoot).CheckExecutionRecovery(context.Background())
			if state == "prepared" && !errors.Is(err, ErrExecutionJournal) || state != "prepared" && err != nil {
				t.Fatal("restart resource fence", state, err)
			}
			after, _ := os.ReadFile(filepath.Join(m.StateRoot, "latest-execution.json"))
			if string(after) != string(data) {
				t.Fatal("read-only inspection rewrote resource outcome")
			}
			if state == "prepared" {
				if err := m.writeExecution(root, execution); !errors.Is(err, ErrExecutionJournal) {
					t.Fatal("writer published an unsettled terminal", err)
				}
			}
		})
	}
}

func TestNetworkPolicyManagerResourceDefinitionAndRootAreBound(t *testing.T) {
	cases := map[string]func(*Execution){
		"foreign plan":          func(e *Execution) { e.Resources[0].NodeTransit.PlanID = "dp-foreign" },
		"foreign digest":        func(e *Execution) { e.Resources[0].NodeTransit.PlanDigest = strings.Repeat("b", 64) },
		"foreign slot":          func(e *Execution) { e.Resources[0].NodeTransit.Priority++ },
		"foreign compiled hash": func(e *Execution) { e.Resources[0].EffectsDigest = strings.Repeat("b", 64) },
		"foreign generation":    func(e *Execution) { e.Resources[0].Generation = strings.Repeat("b", 64) },
		"path traversal":        func(e *Execution) { e.Resources[0].ID = "../nt-0123456789abcdef" },
		"unknown kind":          func(e *Execution) { e.Resources[0].Kind = "commands" },
		"unknown outcome":       func(e *Execution) { e.Resources[0].State = "complete" },
		"duplicate root":        func(e *Execution) { e.Resources = append(e.Resources, e.Resources[0]) },
		"missing typed payload": func(e *Execution) { e.Resources[0].NodeTransit = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			execution := networkPolicyResourceFixture(t, "removed")
			mutate(&execution)
			if err := validateExecutionResources(execution, true); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("different definition acquired recorded authority", err)
			}
		})
	}
	original := networkPolicyResourceFixture(t, "removed")
	copy := cloneExecutionResources(original.Resources)
	copy[0].NodeTransit.PlanID = "dp-other"
	if original.Resources[0].NodeTransit.PlanID == copy[0].NodeTransit.PlanID {
		t.Fatal("resource accessor aliased typed definition")
	}
}

func TestNetworkPolicyManagerTemporaryResourcesKeepOriginalPlanIdentity(t *testing.T) {
	execution := networkPolicyResourceFixture(t, "removed")
	execution.ResourcePlanID = execution.PlanID
	execution.PlanID = "dp-check-0123456789abcdef"
	execution.State = "temporary-complete"
	if err := validateExecutionResources(execution, true); err != nil {
		t.Fatal("private attempt changed immutable plan identity", err)
	}
	execution.State = "committed"
	if err := validateExecutionResources(execution, true); err == nil {
		t.Fatal("temporary operation published a config/plan commit")
	}
}

func TestNetworkPolicyManagerUnsettledResourceCannotFinishPublication(t *testing.T) {
	m := New(t.TempDir())
	execution := networkPolicyResourceFixture(t, "prepared")
	execution.State = "committing"
	execution.Steps = []ExecutionStep{{Adapter: "xray", Phase: "health", State: "passed", FinishedAt: execution.FinishedAt}}
	root := filepath.Join(m.StateRoot, "transactions", execution.PlanID)
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(execution)
	for _, path := range []string{filepath.Join(root, "execution.json"), filepath.Join(m.StateRoot, "latest-execution.json")} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if settled, err := m.settleCommittedPublication(); settled || err != nil {
		t.Fatal("unfinished resource publication was adopted", settled, err)
	}
}
