package app

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

func TestServiceRuntimeStopOrdinaryScopedXray(t *testing.T) {
	a, id, original := nodeApplyFixture(t)
	options := a.nodeReviews.options
	a.nodeReviews.options = func() []routecatalog.Option {
		return append(options(), routecatalog.Option{ID: "xray", Installed: true, Configured: true, Selectable: true})
	}
	adapter := &serviceRuntimeAdapter{nodeApplyAdapter: original, name: "xray"}
	if err := a.Dataplane.Register(adapter); err != nil {
		t.Fatal(err)
	}
	node := "xray:" + id
	scope := []string{"192.168.1.40/32"}
	if _, err := a.Store.ApplyNodeRouteScopeWithRollback("telegram", node, scope, a.Store.Get().Revision); err != nil {
		t.Fatal(err)
	}
	cfg := a.Store.Get()
	plan := dataplane.Plan{PlanID: "dp-" + strings.Repeat("a", 16), Digest: strings.Repeat("a", 64), SchemaVersion: dataplane.SchemaVersion, Ready: true, State: "committed", Revision: cfg.AppliedRevision, Adapters: []string{"xray"}, RouteCount: 1, Routes: []dataplane.Route{{ServiceID: "telegram", LogicalServiceID: "telegram", Selected: node, Resolved: node, Sources: scope, CIDRs: []string{"1.1.1.1/32"}}}}
	for _, tc := range []struct {
		name   string
		change func(*dataplane.Plan)
	}{
		{"changed scope", func(p *dataplane.Plan) { p.Routes[0].Sources = []string{"192.168.1.41/32"} }},
		{"mixed adapters", func(p *dataplane.Plan) { p.Adapters = []string{"xray", "sing-box"} }},
		{"unresolved", func(p *dataplane.Plan) { p.Routes[0].Resolved = "direct" }},
		{"other revision", func(p *dataplane.Plan) { p.Revision++ }},
		{"no-op plan", func(p *dataplane.Plan) { p.Noop = true }},
		{"safe mode", func(p *dataplane.Plan) { p.SafeMode = true }},
		{"DNS suspension", func(p *dataplane.Plan) { p.SuspendDNS = true }},
		{"DNS retirement", func(p *dataplane.Plan) { p.DiscardDNS = true }},
		{"domains", func(p *dataplane.Plan) { p.Routes[0].Domains = []string{"test.example"} }},
		{"unscoped destination", func(p *dataplane.Plan) { p.Routes[0].CIDRs = []string{"0.0.0.0/0"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unsafe := plan
			unsafe.Routes = slices.Clone(plan.Routes)
			tc.change(&unsafe)
			if ordinaryXrayStopPlan(cfg, unsafe) {
				t.Fatal("ambiguous plan handed to ordinary Stop")
			}
		})
	}
	if err := a.Dataplane.Record(plan); err != nil {
		t.Fatal(err)
	}
	initReconcilerFixture(t, a, time.Now())
	job := durableRuntimeAccept(t, a, "stop", "ordinary-xray-panel-stop", cfg.Revision)
	a.runDurableServiceJob(t.Context(), time.Now())
	if result := durableJobAt(t, a, job.ID); result.State != "completed" {
		t.Fatalf("ordinary Stop: state=%s code=%s", result.State, result.RuntimeCode)
	}
	stopped := a.Store.Get()
	if !stopped.ServiceControl.Stopped || len(stopped.AppliedServices) != 0 || stopped.ServiceControl.SuspendedRoutes["telegram"] != node ||
		!reflect.DeepEqual(stopped.ServiceControl.SuspendedServices, cfg.AppliedServices) || !reflect.DeepEqual(stopped.Services, cfg.Services) ||
		strings.Join(adapter.calls, ",") != "snapshot,deactivate" {
		t.Fatalf("scope or retirement incorrect: stopped=%t, adapter calls=%v", stopped.ServiceControl.Stopped, adapter.calls)
	}
	if w := runtimeRequest(a, "resume"); w.Code != 409 || !strings.Contains(w.Body.String(), "SERVICE_RUNTIME_CHECK_REQUIRED") {
		t.Fatalf("unchecked resume: %d %s", w.Code, w.Body.String())
	}
}
