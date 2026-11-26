package dataplane

import (
	"reflect"
	"testing"
)

// Comparison/dispatch regression only. The modeled record fixture has actual
// journal FDs but no native child/source and cannot grant runtime cleanup.
func TestMihomoRestorationUsesOriginalIntentAfterResultBookkeeping(t *testing.T) {
	_, adapter, r, _ := mihomoLiveRecordModel(t)
	r.scope.plan.RouteEvidence = []RouteEvidence{{ServiceID: r.scope.plan.Routes[0].ServiceID, Route: r.scope.plan.Routes[0].Resolved, Required: r.scope.plan.RequiredEvidence}}
	r.definition.Plan = cloneExecutionResourcePlan(r.scope.plan)
	current := cloneExecutionResourcePlan(r.scope.plan)
	current.State, current.Ready, current.Note = "committed", false, "result bookkeeping after desired CAS"
	current.ObservedEvidence, current.EvidenceNote = current.RequiredEvidence, "observed result bookkeeping"
	for i := range current.RouteEvidence {
		current.RouteEvidence[i].Observed = current.RouteEvidence[i].Required
		current.RouteEvidence[i].Source, current.RouteEvidence[i].Note = "adapter-health", "observed result"
	}
	if reflect.DeepEqual(current, r.definition.Plan) {
		t.Fatal("fixture did not reproduce strict frozen-plan mismatch")
	}
	restored, err := originalMihomoRestorationPlan(r.scope, adapter, current)
	if err != nil || !reflect.DeepEqual(restored, r.definition.Plan) {
		left, right := reflect.ValueOf(r.scope.plan), reflect.ValueOf(r.definition.Plan)
		for i := 0; i < left.NumField(); i++ {
			if !reflect.DeepEqual(left.Field(i).Interface(), right.Field(i).Interface()) {
				t.Log("scope/definition difference", left.Type().Field(i).Name)
			}
		}
		t.Fatal("original Manager restoration intent was lost", err)
	}
	restored.Routes[0].CIDRs = []string{"9.9.9.9/32"}
	if reflect.DeepEqual(restored, r.scope.plan) || !reflect.DeepEqual(r.scope.plan, r.definition.Plan) {
		t.Fatal("restoration result aliases original frozen intent")
	}
}

func TestMihomoRestorationRefusesForeignIntentAndDefinition(t *testing.T) {
	for _, name := range []string{"adapter", "digest", "route", "scope", "definition", "evidence-identity"} {
		t.Run(name, func(t *testing.T) {
			_, original, r, _ := mihomoLiveRecordModel(t)
			r.scope.plan.RouteEvidence = []RouteEvidence{{ServiceID: r.scope.plan.Routes[0].ServiceID, Route: r.scope.plan.Routes[0].Resolved, Required: r.scope.plan.RequiredEvidence}}
			r.definition.Plan = cloneExecutionResourcePlan(r.scope.plan)
			current := cloneExecutionResourcePlan(r.scope.plan)
			var adapter Adapter = original
			switch name {
			case "adapter":
				foreign := &MihomoProbeAdapter{}
				foreign.self = foreign
				adapter = foreign
			case "digest":
				current.Digest = "foreign"
			case "route":
				current.Routes[0].CIDRs = []string{"9.9.9.9/32"}
			case "scope":
				current.Routes[0].Sources = []string{"192.168.2.0/24"}
			case "definition":
				r.definition.Plan.Revision++
			case "evidence-identity":
				if len(current.RouteEvidence) == 0 {
					t.Fatal("original route evidence identity required")
				}
				current.RouteEvidence[0].ServiceID = "foreign"
			}
			if _, err := originalMihomoRestorationPlan(r.scope, adapter, current); err == nil {
				t.Fatal("foreign restoration intent accepted")
			}
		})
	}
}
