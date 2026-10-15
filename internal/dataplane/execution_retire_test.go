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
	if err := New(t.TempDir()).retireSettledAttempt(filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Fatal("first attempt refused", err)
	}
}
