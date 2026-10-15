package dataplane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The autopilot retries an identical plan, so a retry reuses the transaction
// root. On the owner's router every retry after one rolled-back attempt failed
// in sing-box Stage on the earlier attempt's receipt.
func TestRetireSettledAttemptMovesOnlyUndoneAttempts(t *testing.T) {
	for state, retire := range map[string]bool{"rolled-back": true, "canary-failed": true, "network-stale": true, "rollback-failed": false, "committed": false, "journal-failed": false} {
		m := New(t.TempDir())
		root := filepath.Join(m.StateRoot, "transactions", "dp-0123456789abcdef")
		if err := os.MkdirAll(filepath.Join(root, "sing-box"), 0o700); err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(Execution{PlanID: "dp-0123456789abcdef", State: state})
		if err := os.WriteFile(filepath.Join(root, "execution.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "sing-box", "policy-additions.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := m.retireSettledAttempt(root); err != nil {
			t.Fatal(state, err)
		}
		_, kept := os.Stat(filepath.Join(root, "sing-box"))
		retired, _ := filepath.Glob(filepath.Join(m.StateRoot, "transactions", ".retired", "dp-0123456789abcdef-*", "sing-box", "policy-additions.json"))
		if (kept != nil) != retire || (len(retired) == 1) != retire {
			t.Fatalf("%s: kept=%v retired=%v", state, kept, retired)
		}
		if _, err := os.Stat(filepath.Join(root, "execution.json")); err != nil {
			t.Fatal(state, "latest attempt record moved", err)
		}
	}
	m := New(t.TempDir())
	if err := m.retireSettledAttempt(filepath.Join(m.StateRoot, "transactions", "absent")); err != nil {
		t.Fatal("first attempt refused", err)
	}
	m = New(filepath.Join(t.TempDir(), "not-created"))
	if err := m.retireSettledAttempt(filepath.Join(m.StateRoot, "transactions", "absent")); err != nil {
		t.Fatal("first state-tree creation refused", err)
	}
}

func TestRetireSettledAttemptRejectsSymlinkDirectoriesBeforeMoving(t *testing.T) {
	for _, target := range []string{"transaction", "transactions", "archive", "state"} {
		t.Run(target, func(t *testing.T) {
			m := New(filepath.Join(t.TempDir(), "state"))
			id := "dp-0123456789abcdef"
			root := filepath.Join(m.StateRoot, "transactions", id)
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(Execution{PlanID: id, State: "rolled-back"})
			if err := os.WriteFile(filepath.Join(root, "execution.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "keep"), []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			outside := t.TempDir()
			link, destination, victim := root, outside, filepath.Join(outside, "keep")
			switch target {
			case "transactions":
				link = filepath.Dir(root)
				victim = filepath.Join(outside, id, "keep")
			case "state":
				link = m.StateRoot
				victim = filepath.Join(outside, "transactions", id, "keep")
			case "archive":
				link = filepath.Join(filepath.Dir(root), ".retired")
				victim = filepath.Join(root, "keep")
			}
			if target != "archive" {
				if err := os.Remove(outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(link, outside); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(destination, link); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			if err := m.retireSettledAttempt(root); err == nil {
				t.Fatal("symlink retirement accepted")
			}
			if data, err := os.ReadFile(victim); err != nil || string(data) != "original" {
				t.Fatal("rejected retirement moved original files", err)
			}
			if target == "archive" {
				entries, err := os.ReadDir(outside)
				if err != nil || len(entries) != 0 {
					t.Fatal("rejected retirement wrote outside the state root", entries, err)
				}
			}
		})
	}
}

func TestRetirementHeldDirectoryDetectsReplacement(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	parent, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	child, err := openRetirementChild(parent, "child")
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	if err := parent.Rename("child", "moved"); err != nil {
		t.Fatal(err)
	}
	if err := parent.Mkdir("child", 0700); err != nil {
		t.Fatal(err)
	}
	if err := checkRetirementChild(parent, "child", child); err == nil {
		t.Fatal("replacement directory acquired the held owner's authority")
	}
}
