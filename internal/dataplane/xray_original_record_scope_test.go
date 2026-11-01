package dataplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestXrayOriginalRecordsBindFiniteExecutionToOriginalPlan(t *testing.T) {
	for _, kind := range []string{"apply", "finite", "foreign-resource-plan", "foreign-digest", "foreign-root", "missing-execution", "noncheck-resource"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			plan := Plan{PlanID: "dp-" + strings.Repeat("a", 16), Digest: strings.Repeat("a", 64)}
			e := &Execution{PlanID: plan.PlanID, Digest: plan.Digest}
			if kind != "apply" {
				e.PlanID, e.ResourcePlanID = "dp-check-"+strings.Repeat("b", 32), plan.PlanID
			}
			s := &executionResourceScope{manager: &Manager{StateRoot: root}, managerRoot: root, root: filepath.Join(root, "transactions", e.PlanID), plan: plan, execution: e}
			if err := os.MkdirAll(s.root, 0700); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "foreign-resource-plan":
				e.ResourcePlanID = "dp-" + strings.Repeat("c", 16)
			case "foreign-digest":
				e.Digest = strings.Repeat("c", 64)
			case "foreign-root":
				s.root = filepath.Join(root, "transactions", plan.PlanID)
			case "missing-execution":
				s.execution = nil
			case "noncheck-resource":
				e.PlanID = plan.PlanID
			}
			records, err := newXraySelectedTCPRecords(s)
			if kind == "apply" || kind == "finite" {
				if err != nil {
					t.Fatal(err)
				}
				if err := records.close(); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || records != nil {
				t.Fatal("foreign record scope accepted", err)
			}
		})
	}
}
