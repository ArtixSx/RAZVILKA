package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAutonomyCompatibilityOnlyReadsBoundedState(t *testing.T) {
	valid, _ := json.Marshal(newAutonomyDocument())
	for _, scenario := range []string{"current", "absent", "future", "broken", "directory", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "state")
			content := string(valid)
			switch scenario {
			case "absent":
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			default:
				if scenario == "future" {
					content = strings.Replace(content, `"schema":1`, `"schema":99`, 1)
				}
				if scenario == "broken" {
					content = `{"private":"not-a-valid-state"`
				}
				if scenario == "oversize" {
					content = strings.Repeat("x", maxAutonomyBytes+1)
				}
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := CheckAutonomyState(path)
			if (err == nil) != (scenario == "current" || scenario == "absent") {
				t.Fatal(scenario, err)
			}
			if scenario == "absent" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("created state")
				}
			} else if scenario != "directory" {
				data, err := os.ReadFile(path)
				if err != nil || string(data) != content {
					t.Fatal("state changed")
				}
			}
		})
	}
}
