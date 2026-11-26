package dataplane

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mihomoColdIntentFixture(t *testing.T) Execution {
	d := mihomoLiveDefinitionFixture(t)
	d.NativeHome = mihomoLiveHomeFixture(t)
	digest, err := d.FrozenDigest()
	if err != nil {
		t.Fatal(err)
	}
	return Execution{PlanID: d.Plan.PlanID, Digest: d.Plan.Digest, State: "resource-failed", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Resources: []ExecutionResource{{ID: "ml-" + strings.Repeat("a", 32), Kind: "mihomo-live", State: "prepared", Phase: "process-pending", Generation: d.Profile.ConfigSHA256, EffectsDigest: digest, MihomoLive: &d}}, Steps: []ExecutionStep{{Adapter: "mihomo", Phase: "activate", State: "running"}}}
}

func TestMihomoLiveColdIntentPreservesOriginalAndRefusesFinalizing(t *testing.T) {
	e := mihomoColdIntentFixture(t)
	raw, _ := json.Marshal(e)
	parsed, d, err := decodeMihomoLiveRetirementIntent(raw)
	if err != nil || d.Plan.PlanID != e.PlanID {
		t.Fatal(err)
	}
	after, err := mihomoLiveRetirementTerminal(parsed, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil || after.RollbackVerified || after.State != "rolled-back" || after.Resources[0].State != "removed" || after.Steps[0].State != "failed" {
		t.Fatal(after, err)
	}
	current, _ := json.Marshal(e)
	if !bytes.Equal(raw, current) {
		t.Fatal("original history mutated")
	}
	oldDefinition, _ := json.Marshal(e.Resources[0].MihomoLive)
	newDefinition, _ := json.Marshal(after.Resources[0].MihomoLive)
	if !bytes.Equal(oldDefinition, newDefinition) {
		t.Fatal("retirement rewrote frozen comparison")
	}
	for _, state := range []string{"committing", "finalizing", "unknown", "new-reader-state"} {
		candidate := e
		candidate.State = state
		data, _ := json.Marshal(candidate)
		if _, _, err := decodeMihomoLiveRetirementIntent(data); err == nil {
			t.Fatal("unsettled/unknown accepted", state)
		}
	}
	for _, data := range [][]byte{append(append([]byte{}, raw...), raw...), bytes.Replace(raw, []byte(`"state":"resource-failed"`), []byte(`"state":"resource-failed","state":"committed"`), 1), bytes.Replace(raw, []byte(`"state":"resource-failed"`), []byte(`"unknown_field":true,"state":"resource-failed"`), 1)} {
		if _, _, err := decodeMihomoLiveRetirementIntent(data); err == nil {
			t.Fatal("ambiguous wire accepted")
		}
	}
}
