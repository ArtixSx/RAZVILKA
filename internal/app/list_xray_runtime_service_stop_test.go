package app

import (
	"context"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Actual source, compiler and Store CAS; the execution struct below is only
// a comparison view. It issues no runtime, terminal or native effect owner.
func TestListXrayStopUsesOriginalLogicalServiceAndConfiguredSources(t *testing.T) {
	f, service := newSelectedTCPInlineScopeFixture(t)
	listScopeOperation(t, f.a, func(ctx context.Context) {
		r, err := f.a.ReviewXrayListRuntimeSource(ctx, f.scope, service.ID, f.adapter)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		p, err := r.prepare(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		defer p.close()
		input := (&DefaultRouteExecutor{app: f.a}).input(p.compilation, r.expected)
		_, started, finished := xrayAssemblySourceCAS(t, r)
		if err := r.acceptCommitted(ctx, started, finished); err != nil {
			t.Fatal(err)
		}
		cfg := f.a.Store.Get()
		if len(input.Routes) != 1 || input.Routes[0].ServiceID == service.ID || input.Routes[0].LogicalServiceID != service.ID ||
			reflect.DeepEqual(cfg.AppliedServices[service.ID].Sources, input.Routes[0].Sources) {
			t.Fatal("fixture did not exercise actual compiled/configured scope difference")
		}
		e := &managedXraySelectedTCPListExecution{source: r, plan: dataplane.Plan{Routes: input.Routes, LAN: p.compilation.LAN()}}
		resolved, err := e.appliedStopRoutes(cfg)
		if err != nil || !reflect.DeepEqual(resolved, map[string]string{service.ID: r.selected}) {
			t.Fatal("actual Stop lost original logical service", resolved, err)
		}
		desired := cfg.Services[service.ID]
		desired.Enabled = false
		if err := f.a.Store.UpdateService(service.ID, desired); err != nil {
			t.Fatal(err)
		}
		beforeStop := f.a.Store.Get()
		if _, err := e.appliedStopRoutes(beforeStop); err != nil {
			t.Fatal("unapplied desired edit changed original cleanup scope", err)
		}
		if _, err := f.a.Store.CommitServiceRuntime(true, resolved, beforeStop.Revision); err != nil {
			t.Fatal("actual Stop CAS refused logical resolved key", err)
		}
		after := f.a.Store.Get()
		if !after.ServiceControl.Stopped || !reflect.DeepEqual(after.Services, beforeStop.Services) ||
			!reflect.DeepEqual(after.ServiceControl.SuspendedServices[service.ID], cfg.AppliedServices[service.ID]) || after.ServiceControl.SuspendedRoutes[service.ID] != r.selected {
			t.Fatal("Stop CAS widened scope or consumed desired edits")
		}
		changed := beforeStop.AppliedServices[service.ID]
		changed.Sources = []string{"192.168.1.41/32"}
		beforeStop.AppliedServices[service.ID] = changed
		if _, err := e.appliedStopRoutes(beforeStop); err == nil {
			t.Fatal("changed applied scope supplied original Stop intent")
		}
	})
}
