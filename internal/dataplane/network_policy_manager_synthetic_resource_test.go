package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Detached journal/comparison intent only. This fixture has no original
// mapping, runtime owner, native receipt, capture, publication or Ready grant.
func executionSyntheticResourceFixture(t *testing.T) Execution {
	t.Helper()
	transport, domain := syntheticTransportModelFixture(t)
	plan, err := BuildAt(Input{DomainPolicy: domain, SyntheticDNS: transport}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	d := &ExecutionSyntheticBaselineDefinition{Schema: 1, PlanID: plan.PlanID, PlanDigest: plan.Digest, DomainDigest: domain.Digest,
		NetworkIdentity: netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "01234567-89ab-cdef-0123-456789abcdef", Inode: 12345},
		Mapping: dnscontrol.SyntheticDNSMappingObservation{
			Authority:     dnscontrol.NetworkPolicyDNSAuthority{Generation: domain.Generation, ControlEpoch: 1, BindingRevision: 1, Exclusions: transport.DNS.Exclusions},
			PublicationID: strings.Repeat("b", 32), Client: transport.Definition.Client, DeviceID: transport.Definition.DeviceID,
			MAC: transport.Definition.MAC, Ingress: transport.Definition.Ingress, QName: transport.Definition.ExactNames[0],
			Synthetic: netip.MustParseAddr("198.18.0.1"), RealIPv4: netip.MustParseAddr("93.184.215.14"), CNAMEChain: []string{"alias.example.com"}, ExpiresAt: time.Unix(200, 0).UTC(),
		}}
	compiled, err := syntheticBaselineDefinitionEffects(d)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := PolicyEffectPlanDigest(compiled)
	if err != nil {
		t.Fatal(err)
	}
	return Execution{PlanID: plan.PlanID, Digest: plan.Digest, State: "applying", StartedAt: time.Unix(100, 0).UTC().Format(time.RFC3339Nano),
		Resources: []ExecutionResource{{ID: "sb-" + strings.Repeat("1", 32), Kind: "synthetic-baseline", State: "prepared", Phase: "baseline-prepared", Generation: compiled.Generation, EffectsDigest: digest, SyntheticBaseline: d}}}
}

func TestNetworkPolicyManagerSyntheticResourceJSONAndDeepClone(t *testing.T) {
	original := executionSyntheticResourceFixture(t)
	encoded, err := json.Marshal(original)
	if err != nil || !strings.Contains(string(encoded), `"synthetic_baseline":`) {
		t.Fatal("typed resource absent from common journal", err)
	}
	var decoded Execution
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := validateExecutionResources(decoded, false); err != nil {
		t.Fatal("journal roundtrip lost structural comparison", err)
	}
	copy := cloneExecutionResources(decoded.Resources)
	copy[0].ID = "sb-" + strings.Repeat("2", 32)
	copy[0].SyntheticBaseline.PlanID = "dp-foreign"
	copy[0].SyntheticBaseline.Mapping.CNAMEChain[0] = "changed.example.com"
	if decoded.Resources[0].ID != original.Resources[0].ID || decoded.Resources[0].SyntheticBaseline.PlanID != original.PlanID || decoded.Resources[0].SyntheticBaseline.Mapping.CNAMEChain[0] != "alias.example.com" {
		t.Fatal("detached copy changed original journal intent")
	}
	if err := validateExecutionResources(decoded, false); err != nil {
		t.Fatal("mutated accessor changed original", err)
	}
	legacy := networkPolicyResourceFixture(t, "removed")
	encoded, err = json.Marshal(legacy)
	if err != nil || strings.Contains(string(encoded), `"synthetic_baseline"`) || cloneExecutionResources(legacy.Resources)[0].SyntheticBaseline != nil {
		t.Fatal("optional field changed legacy journal shape", err)
	}
}

func TestNetworkPolicyManagerSyntheticResourcePhasesKeepTerminalFence(t *testing.T) {
	for _, phase := range []string{"planned", "baseline-prepared", "capture-ready", "transfer-intent", "transfer-ack", "closed"} {
		execution := executionSyntheticResourceFixture(t)
		execution.Resources[0].Phase = phase
		if err := validateExecutionResources(execution, false); err != nil {
			t.Fatal("valid prepared intent refused", phase, err)
		}
		if err := validateExecutionResources(execution, true); !errors.Is(err, ErrExecutionJournal) || !errors.Is(err, ErrPolicyAdditionUnknown) {
			t.Fatal("prepared intent became terminal readiness", phase, err)
		}
	}
	for _, outcome := range []string{"removed", "unused"} {
		execution := executionSyntheticResourceFixture(t)
		execution.Resources[0].State, execution.Resources[0].Phase = outcome, outcome
		if err := validateExecutionResources(execution, true); err != nil {
			t.Fatal("known structural outcome refused", outcome, err)
		}
	}
	for _, phase := range []string{"", "ready", "active", "removed", "unused", "process-pending"} {
		execution := executionSyntheticResourceFixture(t)
		execution.Resources[0].Phase = phase
		if err := validateExecutionResources(execution, false); !errors.Is(err, ErrExecutionJournal) {
			t.Fatal("phase/state substitution accepted", phase, err)
		}
	}
}

func TestNetworkPolicyManagerSyntheticResourceRootAndTypedBindings(t *testing.T) {
	for name, mutate := range map[string]func(*Execution){
		"node-root":          func(e *Execution) { e.Resources[0].ID = "nt-" + strings.Repeat("1", 32) },
		"nfq-root":           func(e *Execution) { e.Resources[0].ID = "nq-" + strings.Repeat("1", 32) },
		"path":               func(e *Execution) { e.Resources[0].ID = "../" + e.Resources[0].ID },
		"uppercase":          func(e *Execution) { e.Resources[0].ID = "sb-" + strings.Repeat("A", 32) },
		"short-id":           func(e *Execution) { e.Resources[0].ID = "sb-1234" },
		"duplicate":          func(e *Execution) { e.Resources = append(e.Resources, e.Resources[0]) },
		"unknown-kind":       func(e *Execution) { e.Resources[0].Kind = "synthetic-ready" },
		"missing-definition": func(e *Execution) { e.Resources[0].SyntheticBaseline = nil },
		"foreign-plan":       func(e *Execution) { e.Resources[0].SyntheticBaseline.PlanID = "dp-fedcba9876543210" },
		"foreign-digest":     func(e *Execution) { e.Resources[0].SyntheticBaseline.PlanDigest = strings.Repeat("e", 64) },
		"effects-digest":     func(e *Execution) { e.Resources[0].EffectsDigest = strings.Repeat("e", 64) },
		"generation":         func(e *Execution) { e.Resources[0].Generation = strings.Repeat("e", 64) },
		"network-identity":   func(e *Execution) { e.Resources[0].SyntheticBaseline.NetworkIdentity = netidentity.Identity{} },
		"schema":             func(e *Execution) { e.Resources[0].SyntheticBaseline.Schema = 2 },
		"active-state":       func(e *Execution) { e.Resources[0].State = "active"; e.Resources[0].Phase = "active" },
		"mixed-node":         func(e *Execution) { spec := nodeTransitFixtureSpec(); e.Resources[0].NodeTransit = &spec },
		"mixed-nfq":          func(e *Execution) { e.Resources[0].NFQWS = &ExecutionNFQWSDefinition{} },
	} {
		t.Run(name, func(t *testing.T) {
			execution := executionSyntheticResourceFixture(t)
			mutate(&execution)
			if err := validateExecutionResources(execution, false); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("foreign or mixed intent accepted", err)
			}
		})
	}
	short := executionSyntheticResourceFixture(t)
	short.Resources[0].ID = "sb-0123456789abcdef"
	if err := validateExecutionResources(short, false); err != nil {
		t.Fatal("existing supported child ID length refused", err)
	}
}

func TestNetworkPolicyManagerSyntheticResourceCannotAttachToLegacyKinds(t *testing.T) {
	d := executionSyntheticResourceFixture(t).Resources[0].SyntheticBaseline
	for _, execution := range []Execution{networkPolicyResourceFixture(t, "removed"), executionNFQWSResourceFixture(t, "removed")} {
		execution.Resources[0].State = "removed"
		if err := validateExecutionResources(execution, true); err != nil {
			t.Fatal("legacy fixture changed", err)
		}
		execution.Resources[0].SyntheticBaseline = cloneExecutionSyntheticBaselineDefinition(d)
		if err := validateExecutionResources(execution, true); !errors.Is(err, ErrExecutionJournal) {
			t.Fatal("legacy kind ignored synthetic payload", execution.Resources[0].Kind, err)
		}
	}
}

func TestNetworkPolicyManagerSyntheticResourceTemporaryRootKeepsOriginalPlan(t *testing.T) {
	execution := executionSyntheticResourceFixture(t)
	execution.Resources[0].State, execution.Resources[0].Phase = "removed", "removed"
	execution.ResourcePlanID, execution.PlanID, execution.State = execution.PlanID, "dp-check-0123456789abcdef", "temporary-complete"
	if err := validateExecutionResources(execution, true); err != nil {
		t.Fatal("attempt root lost original typed plan", err)
	}
	for _, state := range []string{"committing", "committed"} {
		copy := execution
		copy.State = state
		if err := validateExecutionResources(copy, true); !errors.Is(err, ErrExecutionJournal) {
			t.Fatal("private attempt became plan commit", state, err)
		}
	}
	execution.Resources[0].SyntheticBaseline.PlanID = execution.PlanID
	if err := validateExecutionResources(execution, true); !errors.Is(err, ErrExecutionJournal) {
		t.Fatal("attempt ID replaced original definition parent", err)
	}
}

func TestNetworkPolicyManagerSyntheticResourceRestartDoesNotAdoptPreparedIntent(t *testing.T) {
	for _, state := range []string{"prepared", "removed", "unused"} {
		t.Run(state, func(t *testing.T) {
			m := New(t.TempDir())
			execution := executionSyntheticResourceFixture(t)
			execution.State, execution.FinishedAt = "committed", time.Unix(101, 0).UTC().Format(time.RFC3339Nano)
			execution.Resources[0].State = state
			if state != "prepared" {
				execution.Resources[0].Phase = state
			}
			root := filepath.Join(m.StateRoot, "transactions", execution.PlanID)
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			if state == "prepared" {
				if err := m.writeExecution(root, execution); !errors.Is(err, ErrPolicyAdditionUnknown) {
					t.Fatal("writer published unsettled terminal", err)
				}
			}
			data, err := json.Marshal(execution)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{filepath.Join(root, "execution.json"), filepath.Join(m.StateRoot, "latest-execution.json")} {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			err = New(m.StateRoot).CheckExecutionRecovery(context.Background())
			if state == "prepared" && !errors.Is(err, ErrExecutionJournal) || state != "prepared" && err != nil {
				t.Fatal("restart changed structural resource fence", state, err)
			}
			after, err := os.ReadFile(filepath.Join(m.StateRoot, "latest-execution.json"))
			if err != nil || string(after) != string(data) {
				t.Fatal("read-only recovery rewrote outcome", err)
			}
		})
	}
}
