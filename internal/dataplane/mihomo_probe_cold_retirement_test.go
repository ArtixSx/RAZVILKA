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

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Kernel absence is an explicit model here. Native tests separately require
// actual parent death, complete original namespace and real process absence.
func mihomoColdRetirementFixture(t *testing.T) (*Manager, Execution, []byte, context.Context) {
	m, e, _, ctx, _ := mihomoRetirementFixture(t)
	d := e.Resources[0].MihomoProbe
	d.Source.ParentOrigin = components.MihomoProbeParentOrigin{Schema: 1, BootID: d.NetworkIdentity.BootID, PID: 2, StartTicks: 3, ExecutableDevice: 1, ExecutableInode: 4, ExecutableSHA256: strings.Repeat("d", 64), ExecutableSize: 10, PIDNamespaceDevice: 1, PIDNamespaceInode: 5, ProcDevice: 1, ProcInode: 6, DeathSignal: "linux-pdeathsig-sigkill-v1"}
	p := mihomoProbePlan(*d)
	d.PlanID, d.PlanDigest = p.PlanID, p.Digest
	e.ResourcePlanID, e.Digest = p.PlanID, p.Digest
	raw, _ := json.Marshal(e)
	for _, name := range []string{"latest-execution.json", filepath.Join("transactions", e.PlanID, "execution.json")} {
		if err := os.WriteFile(filepath.Join(m.StateRoot, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return m, e, raw, ctx
}

func TestMihomoColdRetirementReusesExactPairAndRetainsFailedHistory(t *testing.T) {
	for _, cut := range []string{"", "manifest", "execution.json", "latest-execution.json"} {
		t.Run(cut, func(t *testing.T) {
			m, e, raw, ctx := mihomoColdRetirementFixture(t)
			observations := 0
			absent := func(c context.Context, d ExecutionMihomoProbeDefinition) (netidentity.Identity, error) {
				observations++
				if c != ctx || d.Source.ParentOrigin != e.Resources[0].MihomoProbe.Source.ParentOrigin {
					t.Fatal("detached source origin")
				}
				return d.NetworkIdentity, nil
			}
			witness := errors.New("original publication cut")
			fault := func(stage string) error {
				if stage == cut {
					return witness
				}
				return nil
			}
			result, err := m.retireMihomoProbeMetadata(ctx, e.PlanID, e.Digest, func(c context.Context) error { return c.Err() }, absent, true, fault)
			if cut != "" {
				if !errors.Is(err, witness) {
					t.Fatal(err)
				}
				m = New(m.StateRoot)
				result, err = m.retireMihomoProbeMetadata(ctx, e.PlanID, e.Digest, func(c context.Context) error { return c.Err() }, absent, true, nil)
			}
			if err != nil || result.State != "temporary-complete" || result.Steps[0].State != "failed" || result.RollbackVerified || observations < 2 || result.Error != mihomoColdRetirementDetail {
				t.Fatal(result, err, observations)
			}
			data, err := os.ReadFile(filepath.Join(m.StateRoot, "mihomo-probe-retirements", e.PlanID, "retirement.json"))
			if err != nil {
				t.Fatal(err)
			}
			var manifest mihomoProbeRetirement
			if json.Unmarshal(data, &manifest) != nil || !manifest.SameBoot || !bytes.Equal(manifest.Before, raw) {
				t.Fatal("original intent lost or mode changed")
			}
		})
	}
}

func TestMihomoColdRetirementRefusesLegacyOriginOrAbsenceFailure(t *testing.T) {
	for _, kind := range []string{"legacy", "parent-active", "pid-namespace", "new-boot", "third-image", "config"} {
		t.Run(kind, func(t *testing.T) {
			m, e, raw, ctx := mihomoColdRetirementFixture(t)
			if kind == "legacy" {
				e.Resources[0].MihomoProbe.Source.ParentOrigin = components.MihomoProbeParentOrigin{}
				p := mihomoProbePlan(*e.Resources[0].MihomoProbe)
				e.Resources[0].MihomoProbe.PlanID, e.Resources[0].MihomoProbe.PlanDigest = p.PlanID, p.Digest
				e.ResourcePlanID, e.Digest = p.PlanID, p.Digest
				raw, _ = json.Marshal(e)
				for _, name := range []string{"latest-execution.json", filepath.Join("transactions", e.PlanID, "execution.json")} {
					if err := os.WriteFile(filepath.Join(m.StateRoot, name), raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			guard := func(c context.Context) error {
				if kind == "config" {
					return ErrReviewChanged
				}
				return c.Err()
			}
			absent := func(_ context.Context, d ExecutionMihomoProbeDefinition) (netidentity.Identity, error) {
				if kind == "parent-active" || kind == "pid-namespace" {
					return netidentity.Identity{}, ErrMihomoProbeRetirement
				}
				current := d.NetworkIdentity
				if kind == "new-boot" {
					current.BootID = "11111111-2222-4333-8444-555555555555"
					if current.BootID == d.NetworkIdentity.BootID {
						current.BootID = "22222222-3333-4444-8555-666666666666"
					}
				}
				return current, nil
			}
			if kind == "third-image" {
				if err := os.WriteFile(filepath.Join(m.StateRoot, "transactions", e.PlanID, "execution.json"), []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := m.retireMihomoProbeMetadata(ctx, e.PlanID, e.Digest, guard, absent, true, nil); err == nil {
				t.Fatal("cold unknown admitted", kind)
			}
			after, err := os.ReadFile(filepath.Join(m.StateRoot, "latest-execution.json"))
			if err != nil || !bytes.Equal(after, raw) {
				t.Fatal("refusal changed original latest", err)
			}
		})
	}
}
