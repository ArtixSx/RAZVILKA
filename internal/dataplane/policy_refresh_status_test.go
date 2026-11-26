package dataplane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CommittedPolicyRefresh must agree with the full Status view it replaces for
// frequent readers.
func TestCommittedPolicyRefreshMatchesStatus(t *testing.T) {
	writeRefresh := func(t *testing.T, m *Manager, planID string) {
		t.Helper()
		data, _ := json.Marshal(PolicyRefresh{PlanID: planID, State: "checked", CheckedAt: "2026-09-28T00:00:00Z"})
		if err := os.WriteFile(filepath.Join(m.StateRoot, "latest-policy-refresh.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plan := func(id, state string) Plan {
		p := networkExecutionPlan()
		p.PlanID, p.Digest, p.State = id, strings.Repeat(id[len(id)-1:], 64), state
		return p
	}
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, m *Manager)
		want    bool
	}{
		{"none", func(*testing.T, *Manager) {}, false},
		{"committed", func(t *testing.T, m *Manager) {
			_ = m.Record(plan("dp-1111111111111111", "committed"))
			writeRefresh(t, m, "dp-1111111111111111")
		}, true},
		{"newer-reviewed-plan", func(t *testing.T, m *Manager) {
			_ = m.Record(plan("dp-1111111111111111", "committed"))
			_ = m.Record(plan("dp-2222222222222222", "reviewed"))
			writeRefresh(t, m, "dp-1111111111111111")
		}, true},
		{"other-plan", func(t *testing.T, m *Manager) {
			_ = m.Record(plan("dp-1111111111111111", "committed"))
			writeRefresh(t, m, "dp-2222222222222222")
		}, false},
		{"no-committed-plan", func(t *testing.T, m *Manager) {
			_ = m.Record(plan("dp-2222222222222222", "rolled-back"))
			writeRefresh(t, m, "dp-2222222222222222")
		}, false},
		{"legacy-latest-only", func(t *testing.T, m *Manager) {
			_ = m.Record(plan("dp-1111111111111111", "committed"))
			if err := os.Remove(filepath.Join(m.StateRoot, "latest-committed-plan.json")); err != nil {
				t.Fatal(err)
			}
			writeRefresh(t, m, "dp-1111111111111111")
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New(t.TempDir())
			tc.prepare(t, m)
			got, err := m.CommittedPolicyRefresh()
			if err != nil || (got != nil) != tc.want {
				t.Fatalf("got=%+v err=%v want=%v", got, err, tc.want)
			}
			status, err := m.Status()
			fromStatus := err == nil && status.PolicyRefresh != nil && status.CommittedPlan != nil && status.PolicyRefresh.PlanID == status.CommittedPlan.PlanID
			if fromStatus != tc.want {
				t.Fatalf("Status disagrees: %v", fromStatus)
			}
		})
	}
}
