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

func TestDomainDNSDetachedHistoryRequiresReader7AfterRemovalAndOlderLatest(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private-original")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	e := detachedDNSExecutionModel(t)
	write := func(record Execution) {
		t.Helper()
		dir := filepath.Join(root, "transactions", record.PlanID)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{filepath.Join(dir, "execution.json"), filepath.Join(root, "latest-execution.json")} {
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, phase := range []string{"standby-detached", "removed"} {
		e.Resources[0].Phase = phase
		if phase == "removed" {
			e.Resources[0].State = "removed"
		}
		write(e)
		if v, seal, err := InspectRetainedExecutionReadVersion(context.Background(), root); err != nil || v != 7 || seal == "" {
			t.Fatal(phase, v, err)
		}
	}
	write(Execution{PlanID: "dp-" + strings.Repeat("d", 16), Digest: strings.Repeat("e", 64), State: "rolled-back"})
	if v, _, err := InspectRetainedExecutionReadVersion(context.Background(), root); err != nil || v != 7 {
		t.Fatal("old latest hid detached retained history", v, err)
	}
}
