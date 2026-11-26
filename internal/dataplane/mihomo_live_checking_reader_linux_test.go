//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMihomoActiveCheckingZeroTransitRequiresReader9InRetainedHistory(t *testing.T) {
	e := mihomoCheckingExecutionFixture(t)
	root := filepath.Join(t.TempDir(), "protected-history")
	write := func(path string, e Execution) {
		t.Helper()
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	write("latest-execution.json", e)
	if version, _, err := InspectRetainedExecutionReadVersion(ctx, root); err != nil || version != 9 {
		t.Fatal("zero-transit check lost its required reader", version, err)
	}
	settled := e
	h := *e.MihomoLiveHealthOperation
	h.Phase = "settled"
	settled.MihomoLiveHealthOperation = &h
	settled.State, settled.FinishedAt = "committed", settled.StartedAt
	write("latest-execution.json", settled)
	if version, _, err := InspectRetainedExecutionReadVersion(ctx, root); err != nil || version != 9 {
		t.Fatal("header lost reader9 after committed ACK", version, err)
	}
	write(filepath.Join("transactions", e.PlanID, "execution.json"), e)
	// A newer unchanged format8 archive cannot hide an older in-flight9.
	_, archive, after := mihomoTransitArchiveFixture(t)
	write(filepath.Join("transactions", archive.PlanID, "execution.json"), archive)
	write("latest-execution.json", after)
	if version, _, err := InspectRetainedExecutionReadVersion(ctx, root); err != nil || version != 9 {
		t.Fatal("newer terminal record hid older check", version, err)
	}
}
