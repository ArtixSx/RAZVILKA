package autonomy

import (
	"reflect"
	"testing"
	"time"
)

func TestFailureRequiresSeparateAttempts(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	var r Runtime
	if r.Observe("a", "wan1", "FAIL", now, 20*time.Second) {
		t.Fatal("single failure switched")
	}
	if r.Observe("a", "wan1", "FAIL", now.Add(19*time.Second), 20*time.Second) {
		t.Fatal("gap ignored")
	}
	if !r.Observe("a", "wan1", "FAIL", now.Add(20*time.Second), 20*time.Second) {
		t.Fatal("second separate failure ignored")
	}
	if r.Observe("a", "wan1", "PASS", now.Add(21*time.Second), 20*time.Second) || r.Failures != 0 {
		t.Fatal("success did not reset quorum")
	}
}
func TestUnknownAndChangedEvidenceResetQuorum(t *testing.T) {
	for _, tc := range []struct{ name, node, wan, verdict string }{{"unknown", "a", "wan1", "INCONCLUSIVE"}, {"network", "a", "wan2", "FAIL"}, {"newnode", "b", "wan1", "FAIL"}, {"misroute", "a", "wan1", "MISROUTED"}} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			var r Runtime
			r.Observe("a", "wan1", "FAIL", now, 20*time.Second)
			if r.Observe(tc.node, tc.wan, tc.verdict, now.Add(time.Minute), 20*time.Second) {
				t.Fatal("unrelated evidence granted switch")
			}
		})
	}
}
func TestSwitchBudgetSurvivesCopyAndClockRollback(t *testing.T) {
	now := time.Now()
	r := Runtime{}
	if !r.ReserveSwitch(now, 2) || !r.ReserveSwitch(now.Add(time.Second), 2) || r.ReserveSwitch(now.Add(2*time.Second), 2) {
		t.Fatal("budget not bounded")
	}
	copy := r.Clone()
	if copy.ReserveSwitch(now.Add(-time.Hour), 2) {
		t.Fatal("clock rollback erased budget")
	}
	if !copy.ReserveSwitch(now.Add(2*time.Hour), 2) {
		t.Fatal("expired budget never recovered")
	}
	if len(r.Switches) != 2 {
		t.Fatal("clone shared slice")
	}
}
func TestCandidateRotationAndBounds(t *testing.T) {
	ids := []string{"a", "b", "c", "d", "e"}
	seen := map[string]bool{}
	cursor := 0
	for i := 0; i < 5; i++ {
		batch, next := CandidateBatch(ids, "b", cursor, 2)
		if len(batch) > 2 {
			t.Fatal("unbounded batch")
		}
		for _, id := range batch {
			if id == "b" {
				t.Fatal("active candidate retested")
			}
			seen[id] = true
		}
		cursor = next
	}
	if len(seen) != 4 {
		t.Fatal("tail starved")
	}
	if out, next := CandidateBatch(nil, "", 7, 2); len(out) != 0 || next != 0 {
		t.Fatal("empty catalog")
	}
	if out, _ := CandidateBatch([]string{"a"}, "a", -5, 9); len(out) != 0 {
		t.Fatal("active-only list")
	}
	if out, _ := CandidateBatch(ids, "", -1, 2); !reflect.DeepEqual(out, []string{"e", "a"}) {
		t.Fatal(out)
	}
}
func TestRuntimeCloneDoesNotShareReserve(t *testing.T) {
	r := Runtime{Reserves: []string{"node-a"}}
	q := r.Clone()
	q.Reserves[0] = "node-b"
	if r.Reserves[0] != "node-a" {
		t.Fatal("reserve aliased")
	}
}
