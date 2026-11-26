//go:build linux

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

func TestMihomoLiveColdHealth9PublicationRequiresOriginalFleet(t *testing.T) {
	m, a, before, _, ctx, identity := mihomoLiveColdRetirementFixture(t)
	before.State, before.FinishedAt = "committed", before.StartedAt
	before.Resources[0].State, before.Resources[0].Phase = "active", "active"
	before.Resources[0].MihomoLive.Observation = &MihomoLiveRuntimeObservation{Schema: 1, SidecarReceiptVersion: 1, SidecarReceiptSHA256: strings.Repeat("a", 64)}
	for i := range before.Steps {
		before.Steps[i].State, before.Steps[i].FinishedAt = "passed", before.StartedAt
	}
	anchor, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	before.MihomoLiveHealthOperation = &ExecutionMihomoLiveHealthOperation{Schema: 1, ID: strings.Repeat("c", 64), PlanID: before.PlanID, PlanDigest: before.Digest, BeforeSHA256: nodeDefaultSourceMaterialHash(anchor), Phase: "settled"}
	if err := validateExecutionResources(before, true); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"latest-execution.json", filepath.Join("transactions", before.PlanID, "execution.json")}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(m.StateRoot, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	observed := 0
	absent := func(context.Context, ExecutionMihomoLiveDefinition) (netidentity.Identity, error) {
		observed++
		return identity, nil
	}
	result, err := m.retireMihomoLiveMetadata(ctx, before.PlanID, before.Digest, a, func(c context.Context) error { return c.Err() }, absent, nil, nil)
	if !errors.Is(err, ErrMihomoLiveRetirement) || result.PlanID != "" || observed != 0 {
		t.Fatal("documentary header bypassed real fleet admission", result.PlanID, err, observed)
	}
	for _, name := range names {
		after, err := os.ReadFile(filepath.Join(m.StateRoot, name))
		if err != nil || !bytes.Equal(after, raw) {
			t.Fatal("unadmitted writer changed original pair", err)
		}
	}
	if _, err := os.Lstat(filepath.Join(m.StateRoot, "mihomo-live-retirements")); !os.IsNotExist(err) {
		t.Fatal("unadmitted writer created archive", err)
	}
}

// Actual protected document scanner, modeled native cleanup only. Neither
// this test nor the retired header issues an original offline proof.
func TestMihomoLiveColdHealth9TerminalRequiresActualReader9(t *testing.T) {
	before := settledMihomoColdHealth9Fixture(t)
	after, err := mihomoLiveRetirementTerminal(before, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "protected-history")
	for _, name := range []string{"latest-execution.json", filepath.Join("transactions", after.PlanID, "execution.json")} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(after)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if version, _, err := InspectRetainedExecutionReadVersion(ctx, root); err != nil || version != 9 {
		t.Fatal("offline retirement downgraded the actual retained reader", version, err)
	}
	if err := New(root).CheckExecutionRecovery(ctx); err != nil {
		t.Fatal("acknowledged documentary terminal pair rejected", err)
	}
}
