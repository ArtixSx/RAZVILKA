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

func executionNFQWSResourceFixture(t *testing.T, phase string) Execution {
	t.Helper()
	plan, spec, _ := nfqwsScopedFixture(t)
	plan.PlanID = "dp-0123456789abcdef"
	plan.NetworkProfileID = "wan-0123456789ab"
	compiled, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil {
		t.Fatal(err)
	}
	return Execution{PlanID: plan.PlanID, Digest: plan.Digest, State: "applying", StartedAt: time.Unix(100, 0).UTC().Format(time.RFC3339Nano),
		Resources: []ExecutionResource{{ID: "nq-" + strings.Repeat("1", 32), Kind: "nfqws-scoped", State: "prepared", Phase: phase,
			Generation: compiled.Resources().Generation, EffectsDigest: compiled.Digest(), NFQWS: &ExecutionNFQWSDefinition{Plan: cloneExecutionResourcePlan(plan), Spec: compiled.Spec()}}}}
}

func TestNetworkPolicyManagerNFQWSResourceDefinitionAndPhasesAreFrozen(t *testing.T) {
	for _, phase := range []string{"planned", "process-pending", "capture-ready", "closed"} {
		execution := executionNFQWSResourceFixture(t, phase)
		if err := validateExecutionResources(execution, false); err != nil {
			t.Fatal(phase, err)
		}
		if err := validateExecutionResources(execution, true); !errors.Is(err, ErrExecutionJournal) {
			t.Fatal("pending NFQ process/capture published terminal", phase, err)
		}
	}
	cases := map[string]func(*Execution){
		"queue":            func(e *Execution) { e.Resources[0].NFQWS.Spec.Queue++ },
		"candidate":        func(e *Execution) { e.Resources[0].NFQWS.Spec.Candidate.Incarnation = strings.Repeat("2", 32) },
		"traffic":          func(e *Execution) { e.Resources[0].NFQWS.Spec.Candidate.Traffic[0].Last++ },
		"process":          func(e *Execution) { e.Resources[0].NFQWS.Spec.SessionID = strings.Repeat("2", 32) },
		"command":          func(e *Execution) { e.Resources[0].NFQWS.Spec.CommandSHA256 = strings.Repeat("2", 64) },
		"foreign plan":     func(e *Execution) { e.Resources[0].NFQWS.Plan.PlanID = "dp-fedcba9876543210" },
		"ingress":          func(e *Execution) { e.Resources[0].NFQWS.Plan.Routes[0].Ingress[0] = "foreign" },
		"missing full LAN": func(e *Execution) { e.Resources[0].NFQWS.Plan.LAN = nil },
		"mixed kind":       func(e *Execution) { spec := nodeTransitFixtureSpec(); e.Resources[0].NodeTransit = &spec },
		"unknown phase":    func(e *Execution) { e.Resources[0].Phase = "started" },
		"unused":           func(e *Execution) { e.Resources[0].State = "unused" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			execution := executionNFQWSResourceFixture(t, "capture-ready")
			mutate(&execution)
			if err := validateExecutionResources(execution, false); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("different resource definition acquired retained identity", err)
			}
		})
	}
	removed := executionNFQWSResourceFixture(t, "removed")
	removed.Resources[0].State = "removed"
	if err := validateExecutionResources(removed, true); err != nil {
		t.Fatal("known removed metadata shape refused", err)
	}
}

func TestNetworkPolicyManagerNFQWSResourceDeepCloneDoesNotAliasCompilerInput(t *testing.T) {
	original := executionNFQWSResourceFixture(t, "planned")
	copy := cloneExecutionResources(original.Resources)
	copy[0].NFQWS.Plan.Routes[0].Sources[0] = "10.0.0.0/8"
	copy[0].NFQWS.Plan.LAN.Ingress[0].Sources[0] = "10.0.0.0/8"
	copy[0].NFQWS.Spec.Candidate.Traffic[0].First++
	if err := validateExecutionResources(original, false); err != nil {
		t.Fatal("detached accessor changed original compiler input", err)
	}
	if err := validateExecutionResources(Execution{PlanID: original.PlanID, Digest: original.Digest, Resources: copy}, false); err == nil {
		t.Fatal("altered clone retained compiler identity")
	}
}

func TestNetworkPolicyManagerNFQWSResourceRestartNeverAdoptsPendingProcess(t *testing.T) {
	for _, phase := range []string{"planned", "process-pending", "capture-ready", "closed"} {
		t.Run(phase, func(t *testing.T) {
			m := New(t.TempDir())
			execution := executionNFQWSResourceFixture(t, phase)
			execution.State = "committed"
			execution.FinishedAt = time.Unix(101, 0).UTC().Format(time.RFC3339Nano)
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
			if err := New(m.StateRoot).CheckExecutionRecovery(context.Background()); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("restart promoted pending/closed process to terminal", err)
			}
			after, _ := os.ReadFile(filepath.Join(m.StateRoot, "latest-execution.json"))
			if string(after) != string(data) {
				t.Fatal("read-only restart rewrote NFQ disposition")
			}
		})
	}
}
