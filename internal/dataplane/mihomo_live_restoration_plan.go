package dataplane

import "reflect"

// The Manager may already have changed result bookkeeping when final native
// health fails. Cleanup still compares the SAME original frozen intent, never
// a replayed plan or newly compiled replacement. This helper issues no owner,
// admission, process or packet permission; all ordinary phase checks remain.
func originalMihomoRestorationPlan(scope *executionResourceScope, adapter Adapter, current Plan) (Plan, error) {
	a, typed := adapter.(*MihomoProbeAdapter)
	if !typed || a == nil || a.self != a || scope == nil || scope.adapter != "mihomo" || scope.adapterOwner != a || scope.mihomoLive == nil {
		return Plan{}, errMihomoLiveMaterial
	}
	r := scope.mihomoLive
	if r.self != r || r.scope != scope || r.adapter != a || !reflect.DeepEqual(r.definition.Plan, scope.plan) {
		return Plan{}, errMihomoLiveMaterial
	}
	comparison := cloneExecutionResourcePlan(current)
	comparison.State, comparison.Ready, comparison.Note = scope.plan.State, scope.plan.Ready, scope.plan.Note
	comparison.ObservedEvidence, comparison.EvidenceNote = scope.plan.ObservedEvidence, scope.plan.EvidenceNote
	if len(comparison.RouteEvidence) != len(scope.plan.RouteEvidence) {
		return Plan{}, errMihomoLiveMaterial
	}
	for i := range comparison.RouteEvidence {
		comparison.RouteEvidence[i].Observed = scope.plan.RouteEvidence[i].Observed
		comparison.RouteEvidence[i].Source = scope.plan.RouteEvidence[i].Source
		comparison.RouteEvidence[i].Note = scope.plan.RouteEvidence[i].Note
	}
	if !reflect.DeepEqual(comparison, scope.plan) {
		return Plan{}, errMihomoLiveMaterial
	}
	return r.definition.Clone().Plan, nil
}
