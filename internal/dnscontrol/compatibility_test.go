package dnscontrol

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckStateNeverMigratesOrCreatesFiles(t *testing.T) {
	for _, test := range []struct {
		name, data string
		pass       bool
	}{
		{"old", `{"schema":4,"draft":{"profile_id":"automatic"},"applied":{"profile_id":"automatic"}}`, true},
		{"current", `{"schema":5}`, true},
		{"future", `{"schema":6}`, false},
		{"corrupt", `{`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(test.data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := CheckState(path); (err == nil) != test.pass {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != test.data {
				t.Fatal("compatibility check rewrote state", err)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "absent", "state.json")
	if err := CheckState(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("compatibility check created state directory")
	}
}
