package app

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Actual source, compiler and Store CAS. The execution below is an intent
// comparison only; it cannot issue a runtime, terminal or native effect.
func TestListWGStopKeepsOriginalLogicalServiceAndAppliedScope(t *testing.T) {
	f := newListWGSourceFixture(t)
	f.a.Catalog.Services[0].Name, f.a.Catalog.Services[0].Category = "Listed fixture", "fixture"
	f.a.Catalog.Services[0].Strategy = []string{"wireguard"}
	listScopeOperation(t, f.a, func(ctx context.Context) {
		r, err := f.a.ReviewWGListRuntimeSource(ctx, f.scope, "listed")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		p, err := r.Prepare(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		input, err := p.Input(ctx)
		if err != nil {
			t.Fatal(err)
		}
		before := f.a.Store.Get()
		started := time.Now()
		undo, err := f.a.Store.CommitNetworkPolicyWithRollback(before, p.compilation.Policy(), defaultRouteCloneServices(before.Services))
		finished := time.Now()
		if err != nil {
			t.Fatal(err)
		}
		_ = undo
		if err := r.acceptWGCommitted(ctx, started, finished); err != nil {
			t.Fatal(err)
		}
		cfg := f.a.Store.Get()
		if len(input.Routes) == 0 || input.Routes[0].ServiceID == "listed" || input.Routes[0].LogicalServiceID != "listed" || reflect.DeepEqual(cfg.AppliedServices["listed"].Sources, input.Routes[0].Sources) {
			t.Fatal("actual compiler/configuration scope difference missing")
		}
		e := &managedWGListExecution{source: r, plan: dataplane.Plan{Routes: input.Routes, LAN: p.compilation.LAN()}}
		resolved, err := e.appliedStopRoutes(cfg)
		if err != nil || !reflect.DeepEqual(resolved, map[string]string{"listed": "wireguard"}) {
			t.Fatal("original logical Stop intent lost", resolved, err)
		}
		desired := cfg.Services["listed"]
		desired.Enabled = false
		if err := f.a.Store.UpdateService("listed", desired); err != nil {
			t.Fatal(err)
		}
		stopBefore := f.a.Store.Get()
		if _, err := e.appliedStopRoutes(stopBefore); err != nil {
			t.Fatal("unapplied desired edit changed original cleanup scope", err)
		}
		if _, err := f.a.Store.CommitServiceRuntime(true, resolved, stopBefore.Revision); err != nil {
			t.Fatal(err)
		}
		after := f.a.Store.Get()
		if !after.ServiceControl.Stopped || !reflect.DeepEqual(after.Services, stopBefore.Services) || !reflect.DeepEqual(after.ServiceControl.SuspendedServices["listed"], cfg.AppliedServices["listed"]) || after.ServiceControl.SuspendedRoutes["listed"] != "wireguard" {
			t.Fatal("Stop CAS widened or erased original desired/applied images")
		}
		changed := stopBefore.AppliedServices["listed"]
		changed.Sources = []string{"192.168.1.41/32"}
		stopBefore.AppliedServices["listed"] = changed
		if _, err := e.appliedStopRoutes(stopBefore); err == nil {
			t.Fatal("changed applied source supplied original Stop")
		}
	})
}
