//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/privaterestore"
)

func TestMihomoSameBootInputCandidatePredicateRefusesOtherPhasesAndPair(t *testing.T) {
	for _, kind := range []string{"candidate", "committing", "unknown", "finalizing", "sidecar-bound", "sidecar-pending", "partial-pair", "inflight-transit"} {
		t.Run(kind, func(t *testing.T) {
			sameBootInputsFixture(t, func(ctx context.Context, set *privaterestore.OfflineServiceControlSet, state string, e Execution) {
				e.State = "applying"
				e.FinishedAt = ""
				e.Resources[0].State = "prepared"
				e.Resources[0].Phase = "policy-pending"
				switch kind {
				case "committing", "unknown", "finalizing":
					e.State = kind
				case "sidecar-bound", "sidecar-pending":
					e.Resources[0].Phase = kind
				case "inflight-transit":
					spec := nodeTransitFixtureSpec()
					d := e.Resources[0].MihomoLive
					spec.Engine, spec.PlanID, spec.PlanDigest = "mihomo", e.PlanID, e.Digest
					spec.BootID, spec.NetworkProfile, spec.RuntimeID = d.NetworkIdentity.BootID, d.NetworkProfile, d.Profile.ConfigSHA256
					spec.Interface, spec.Table, spec.Priority = d.Policy.Interface, d.Policy.Table, 80
					plan, err := CompileNodeTransit(spec)
					if err != nil {
						t.Fatal(err)
					}
					digest, err := PolicyEffectPlanDigest(plan)
					if err != nil {
						t.Fatal(err)
					}
					e.Resources = append(e.Resources, ExecutionResource{ID: "nt-11111111111111111111111111111111", Kind: "node-transit", State: "prepared", Generation: plan.Generation, EffectsDigest: digest, NodeTransit: &spec})
					if err := validateExecutionResources(e, false); err != nil {
						t.Fatal("fixture must be a valid inflight transit", err)
					}
				}
				raw, err := json.Marshal(e)
				if err != nil {
					t.Fatal(err)
				}
				for n, name := range []string{"latest-execution.json", filepath.Join("transactions", e.PlanID, "execution.json")} {
					if kind == "partial-pair" && n == 1 {
						continue
					}
					if err := os.WriteFile(filepath.Join(state, name), raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
				i, err := holdMihomoSameBootInputs(ctx, set, state, e.PlanID, e.Digest)
				if kind == "candidate" {
					if err != nil || i == nil || !i.candidate {
						t.Fatal("exact comparison candidate refused", err)
					}
					_ = i.close()
					return
				}
				if i != nil || err == nil {
					if i != nil {
						_ = i.close()
					}
					t.Fatal("other phase/partial pair accepted", kind)
				}
			})
		})
	}
}

func TestMihomoSameBootCandidateRefusesOrphanPriorSamePolicyGeneration(t *testing.T) {
	sameBootInputsFixture(t, func(ctx context.Context, set *privaterestore.OfflineServiceControlSet, state string, e Execution) {
		i, err := holdMihomoSameBootInputs(ctx, set, state, e.PlanID, e.Digest)
		if err != nil {
			t.Fatal(err)
		}
		defer i.close()
		i.candidate = true // Private comparison fixture; grants no native source.
		a, err := NewProxyTunnelAdapter("mihomo", nil, state)
		if err != nil {
			t.Fatal(err)
		}
		path, err := a.policyGenerationRoot(strings.Repeat("b", 32))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		options := policyAdditionOptions{boot: func() (string, error) { return i.definition.NetworkIdentity.BootID, nil }}
		if err := applyPolicyAddition(ctx, &recordedPolicyFakeRunner{}, "ip", i.definition.Policy, path, options); err != nil {
			t.Fatal("modeled prior actual receipt writer", err)
		}
		before, err := readMihomoColdRuntime(i.roots[0], "mihomo", a)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateMihomoColdRuntime(a, i.definition, before); err != nil {
			t.Fatal("generic cold comparison must recognize prior same-policy generation", err)
		}
		if held, err := holdMihomoSameBootStatic(ctx, i, a, before); held != nil || err == nil {
			if held != nil {
				_ = held.close()
			}
			t.Fatal("first candidate lane adopted prior unremoved generation")
		}
	})
}
