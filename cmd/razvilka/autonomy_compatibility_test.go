package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
