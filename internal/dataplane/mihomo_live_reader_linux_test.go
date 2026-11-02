//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMihomoLiveHistoryRequiresReader6ForEveryRetainedPhase(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private-history")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	d := mihomoLiveDefinitionFixture(t)
	digest, _ := d.FrozenDigest()
	e := Execution{PlanID: d.Plan.PlanID, Digest: d.Plan.Digest, State: "resource-failed", Resources: []ExecutionResource{{ID: "ml-" + strings.Repeat("a", 32), Kind: "mihomo-live", State: "prepared", Phase: "process-pending", Generation: d.Profile.ConfigSHA256, EffectsDigest: digest, MihomoLive: &d}}}
	write := func(e Execution) {
		t.Helper()
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(root, "transactions", e.PlanID)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{filepath.Join(dir, "execution.json"), filepath.Join(root, "latest-execution.json")} {
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, phase := range []string{"reserved", "validation-pending", "process-pending", "listener-bound", "sidecar-pending", "closed", "removed", "unused"} {
		e.Resources[0].Phase = phase
		e.Resources[0].State = "prepared"
		if phase == "removed" || phase == "unused" {
			e.Resources[0].State = phase
		}
		write(e)
		if version, seal, err := InspectRetainedExecutionReadVersion(context.Background(), root); err != nil || version != 6 || seal == "" {
			t.Fatal(phase, version, err)
		}
	}
	legacy := Execution{PlanID: "dp-" + strings.Repeat("d", 16), Digest: strings.Repeat("e", 64), State: "rolled-back"}
	write(legacy)
	if version, _, err := InspectRetainedExecutionReadVersion(context.Background(), root); err != nil || version != 6 {
		t.Fatal("legacy latest hid retained live format", version, err)
	}
	path := filepath.Join(root, "transactions", e.PlanID, "execution.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(raw), `"mihomo_live":{`, `"mihomo_live":{"future_authority":true,`, 1)
	if changed == string(raw) {
		t.Fatal("missing actual live union")
	}
	if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := InspectRetainedExecutionReadVersion(context.Background(), root); err == nil {
		t.Fatal("unknown retained format treated as reader6")
	}
}
