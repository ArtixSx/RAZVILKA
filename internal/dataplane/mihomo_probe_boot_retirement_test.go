package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func mihomoRetirementFixture(t *testing.T) (*Manager, Execution, []byte, context.Context, netidentity.Identity) {
	t.Helper()
	d := mihomoProbeDefinitionFixture(t)
	p := mihomoProbePlan(d)
	d.PlanID, d.PlanDigest = p.PlanID, p.Digest
	e := Execution{PlanID: "dp-check-" + strings.Repeat("a", 32), ResourcePlanID: p.PlanID, Digest: p.Digest, State: "checking", StartedAt: "2026-11-01T01:02:03Z",
		Steps:     []ExecutionStep{{Adapter: "mihomo", Phase: "health", State: "running", StartedAt: "2026-11-01T01:02:03Z"}},
		Resources: []ExecutionResource{{ID: "mp-" + strings.Repeat("b", 32), Kind: "mihomo-probe", Phase: "process-pending", State: "prepared", Generation: d.Source.ConfigSHA256, EffectsDigest: d.Source.ConfigSHA256, MihomoProbe: &d}}}
	m := New(filepath.Join(t.TempDir(), "private-dataplane"))
	if err := os.MkdirAll(filepath.Join(m.StateRoot, "transactions", e.PlanID), 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(e)
	for _, name := range []string{"latest-execution.json", filepath.Join("transactions", e.PlanID, "execution.json")} {
		if err := os.WriteFile(filepath.Join(m.StateRoot, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	identity := d.NetworkIdentity
	identity.BootID = "11111111-2222-4333-8444-555555555555"
	if identity.BootID == d.NetworkIdentity.BootID {
		t.Fatal("fixture boot was not changed")
	}
	return m, e, raw, ctx, identity
}

func TestMihomoProbeBootRetirementResumesPartialPublication(t *testing.T) {
	for _, cut := range []string{"", "manifest", "execution.json", "latest-execution.json"} {
		t.Run(cut, func(t *testing.T) {
			m, e, raw, ctx, current := mihomoRetirementFixture(t)
			observations := 0
			observe := func(c context.Context, old netidentity.Identity, port int) (netidentity.Identity, error) {
				observations++
				if c != ctx || old != e.Resources[0].MihomoProbe.NetworkIdentity || port != 18090 {
					t.Fatal("detached observation")
				}
				return current, nil
			}
			guard := func(c context.Context) error { return c.Err() }
			cutErr := errors.New("power loss after durable publication")
			fault := func(stage string) error {
				if stage == cut {
					return cutErr
				}
				return nil
			}
			result, err := m.retireMihomoProbeAfterBoot(ctx, e.PlanID, e.Digest, guard, observe, fault)
			if cut != "" {
				if !errors.Is(err, cutErr) || result.PlanID != "" {
					t.Fatal("partial operation reported success", result, err)
				}
				// Resume from a new cold Manager, including another boot between
				// the two durable record writes. No prior observation is reused.
				current.BootID = "22222222-3333-4444-8555-666666666666"
				m = New(m.StateRoot)
				result, err = m.retireMihomoProbeAfterBoot(ctx, e.PlanID, e.Digest, guard, observe, nil)
			}
			if err != nil || result.State != "temporary-complete" || result.Steps[0].State != "failed" || result.RollbackVerified || result.Resources[0].Phase != "removed" || observations < 2 {
				t.Fatal("retirement missing fresh absence or inflated result", result, err, observations)
			}
			if err := m.CheckExecutionRecovery(ctx); err != nil {
				t.Fatal("cold panel remains fenced after complete retirement", err)
			}
			manifestRaw, err := os.ReadFile(filepath.Join(m.StateRoot, "mihomo-probe-retirements", e.PlanID, "retirement.json"))
			if err != nil {
				t.Fatal(err)
			}
			var manifest mihomoProbeRetirement
			if json.Unmarshal(manifestRaw, &manifest) != nil || !bytes.Equal(manifest.Before, raw) {
				t.Fatal("original history was not retained verbatim")
			}
			if _, err := m.retireMihomoProbeAfterBoot(ctx, e.PlanID, e.Digest, guard, observe, nil); err != nil {
				t.Fatal("idempotent explicit retry failed", err)
			}
		})
	}
}

func TestMihomoProbeBootRetirementRefusesUnknownOrStaleState(t *testing.T) {
	for _, mode := range []string{"same-boot", "unknown-absence", "changed-identity", "changed-guard", "foreign-journal", "different-engine", "tampered-manifest", "changed-during-closing-observation"} {
		t.Run(mode, func(t *testing.T) {
			m, e, original, ctx, current := mihomoRetirementFixture(t)
			calls := 0
			guard := func(context.Context) error {
				if mode == "changed-guard" {
					return errors.New("offline owner lost")
				}
				return nil
			}
			observe := func(context.Context, netidentity.Identity, int) (netidentity.Identity, error) {
				calls++
				switch mode {
				case "same-boot":
					return e.Resources[0].MihomoProbe.NetworkIdentity, nil
				case "unknown-absence":
					return current, errors.New("incomplete socket table")
				case "changed-identity":
					if calls > 1 {
						current.Inode++
					}
				case "changed-during-closing-observation":
					if calls == 4 {
						if err := os.WriteFile(filepath.Join(m.StateRoot, "latest-execution.json"), []byte("{}"), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				return current, nil
			}
			if mode == "foreign-journal" {
				if err := os.WriteFile(filepath.Join(m.StateRoot, "transactions", e.PlanID, "execution.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "different-engine" {
				e.Steps[0].Adapter = "sing-box"
				raw, _ := json.Marshal(e)
				for _, name := range []string{"latest-execution.json", filepath.Join("transactions", e.PlanID, "execution.json")} {
					if err := os.WriteFile(filepath.Join(m.StateRoot, name), raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if mode == "tampered-manifest" {
				_, _ = m.retireMihomoProbeAfterBoot(ctx, e.PlanID, e.Digest, guard, observe, func(string) error { return errors.New("cut") })
				path := filepath.Join(m.StateRoot, "mihomo-probe-retirements", e.PlanID, "retirement.json")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var manifest mihomoProbeRetirement
				_ = json.Unmarshal(raw, &manifest)
				manifest.After = original
				raw, _ = json.Marshal(manifest)
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			result, err := m.retireMihomoProbeAfterBoot(ctx, e.PlanID, e.Digest, guard, observe, nil)
			if err == nil || result.PlanID != "" {
				t.Fatal("unknown/stale operation succeeded", result, err, calls)
			}
			if mode == "same-boot" || mode == "unknown-absence" || mode == "changed-guard" {
				raw, _ := os.ReadFile(filepath.Join(m.StateRoot, "latest-execution.json"))
				if !bytes.Equal(raw, original) {
					t.Fatal("preflight refusal changed history")
				}
			}
		})
	}
}
