package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMainDNSCompatibilityDoesNotStartOrMigrateApplication(t *testing.T) {
	for _, scenario := range []struct {
		name, content string
		pass          bool
	}{
		{"old", `{"schema":4}`, true}, {"future", `{"schema":99}`, false}, {"absent", "", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			base := t.TempDir()
			path := filepath.Join(base, "dns-state")
			if scenario.content != "" {
				if err := os.WriteFile(path, []byte(scenario.content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			output, err := runPrivateRecoveryChild(t, base, "check-dns-state")
			if (err == nil) != scenario.pass || scenario.pass && !strings.Contains(output, `{"ok":true}`) {
				t.Fatal(output, err)
			}
			entries, err := os.ReadDir(base)
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if scenario.content != "" {
				want = 1
			}
			if len(entries) != want {
				t.Fatal("read-only command created application state", entries)
			}
			if want != 0 {
				data, err := os.ReadFile(path)
				if err != nil || string(data) != scenario.content {
					t.Fatal("DNS schema migrated during compatibility check", err)
				}
			}
		})
	}
}
