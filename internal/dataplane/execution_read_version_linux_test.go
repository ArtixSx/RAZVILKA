//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRetainedExecutionReaderScansOlderTransactions(t *testing.T) {
	root := t.TempDir()
	d := xrayDomainExecutionDefinitionFixture(t)
	plan, err := compileDomainTCPCaptureEffects(d.Capture, d.Mapping)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := PolicyEffectPlanDigest(plan)
	e := Execution{PlanID: d.PlanID, Digest: d.PlanDigest, State: "applying", Resources: []ExecutionResource{{ID: "dc-" + strings.Repeat("a", 32), Kind: "domain-tcp-capture", State: "prepared", Phase: "planned", Generation: plan.Generation, EffectsDigest: digest, DomainTCPCapture: &ExecutionDomainTCPCaptureDefinition{Schema: 1, Process: d}}}}
	dir := filepath.Join(root, "transactions", e.PlanID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(e)
	if err := os.WriteFile(filepath.Join(dir, "execution.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	legacy := Execution{PlanID: "p-" + strings.Repeat("b", 32), Digest: strings.Repeat("b", 64), State: "rolled-back"}
	latest, _ := json.Marshal(legacy)
	if err := os.WriteFile(filepath.Join(root, "latest-execution.json"), latest, 0600); err != nil {
		t.Fatal(err)
	}
	v, seal, err := InspectRetainedExecutionReadVersion(context.Background(), root)
	if err != nil || v != 2 || seal == "" {
		t.Fatal("old retained new format overlooked", v, err)
	}
	e.Error = "changed retained observation"
	data, _ = json.Marshal(e)
	if err := os.WriteFile(filepath.Join(dir, "execution.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	_, changed, err := InspectRetainedExecutionReadVersion(context.Background(), root)
	if err != nil || changed == seal {
		t.Fatal("history mutation did not change seal", err)
	}
	manager := New(root)
	for _, state := range []string{"checking", "resource-failed"} {
		e.State = state
		if err := manager.writeExecution(dir, e); err != nil {
			t.Fatal("actual writer publication", state, err)
		}
		if version, _, err := InspectRetainedExecutionReadVersion(context.Background(), root); err != nil || version != 2 {
			t.Fatal("own publication cut unreadable", state, version, err)
		}
		if manager.CheckExecutionRecovery(context.Background()) == nil {
			t.Fatal("format readability waived unfinished recovery", state)
		}
	}
}

func TestRetainedExecutionReaderRejectsUnknownAndSpecialFiles(t *testing.T) {
	for _, kind := range []string{"unknown-field", "unknown-kind", "duplicate-key", "symlink", "hardlink", "fifo", "writable"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "latest-execution.json")
			data := []byte(`{"plan_id":"p-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"rolled-back"}`)
			switch kind {
			case "duplicate-key":
				data = []byte(`{"plan_id":"p-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"future","state":"rolled-back"}`)
			case "unknown-field":
				data = []byte(`{"plan_id":"p-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","future":true}`)
			case "unknown-kind":
				data = []byte(`{"plan_id":"p-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resources":[{"kind":"future"}]}`)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Rename(path, path+"-target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+"-target", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+"-link"); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := InspectRetainedExecutionReadVersion(context.Background(), root); err == nil {
				t.Fatal("unsafe history accepted")
			}
		})
	}
}
