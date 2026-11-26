package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/autonomy"
)

func TestMainAutonomyCompatibilityDoesNotOpenStores(t *testing.T) {
	for _, present := range []bool{false, true} {
		base := t.TempDir()
		path := filepath.Join(base, "config.automation.json.autonomy.json")
		content := `{"private":"invalid, must not appear in diagnostics"}`
		if present {
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
		}
		output, err := runPrivateRecoveryChild(t, base, "check-autonomy-state")
		if (err == nil) == present || !present && !strings.Contains(output, `{"ok":true}`) || strings.Contains(output, "must not appear") {
			t.Fatal(output, err)
		}
		entries, err := os.ReadDir(base)
		want := 0
		if present {
			want = 1
		}
		if err != nil || len(entries) != want {
			t.Fatal("compatibility command opened stores", entries, err)
		}
		if present {
			data, err := os.ReadFile(path)
			if err != nil || string(data) != content {
				t.Fatal("state changed")
			}
		}
	}
}

func TestMainAutonomyCompatibilityReadsSavedMASQUEConsent(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "config.automation.json.autonomy.json")
	policy := autonomy.Default()
	policy.PreferredRoutes = []string{"usque"}
	policy.AllowInitialMASQUERegistration = true
	data, err := json.Marshal(map[string]any{"schema": 1, "owner": "razvilka-autonomy-v1", "policy": policy})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	output, err := runPrivateRecoveryChild(t, base, "check-autonomy-state")
	if err != nil || !strings.Contains(output, "{\"ok\":true}\n") {
		t.Fatal(output, err)
	}
	fresh, err := os.ReadFile(path)
	if err != nil || string(fresh) != string(data) {
		t.Fatal("autonomy check changed user consent", err)
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 1 {
		t.Fatal("autonomy check created extra state", entries, err)
	}
}

func TestMainAutonomyCompatibilityReadsSavedWARPConsent(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		base := t.TempDir()
		path := filepath.Join(base, "config.automation.json.autonomy.json")
		policy := autonomy.Default()
		policy.PreferredRoutes = []string{"warp-wg"}
		policy.AllowInitialWARPRegistration = &allowed
		data, err := json.Marshal(map[string]any{"schema": 1, "owner": "razvilka-autonomy-v1", "policy": policy})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		output, err := runPrivateRecoveryChild(t, base, "check-autonomy-state")
		if err != nil || !strings.Contains(output, "{\"ok\":true}\n") {
			t.Fatal(output, err)
		}
		fresh, err := os.ReadFile(path)
		if err != nil || string(fresh) != string(data) {
			t.Fatal("compatibility check changed the saved WARP choice", err)
		}
		entries, err := os.ReadDir(base)
		if err != nil || len(entries) != 1 {
			t.Fatal("compatibility check created extra state", entries, err)
		}
	}
}
