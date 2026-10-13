package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Actual source, Store receipt, private NodeStore and selected-device compiler.
// Only physical acquisition, WAN and recorded health use explicit models.
// The plan below is a comparison view; no runtime/native health is fabricated.
func TestAutonomyManagedXrayHealthyComparisonKeepsLogicalIDAndCompiledScopeAcrossRounds(t *testing.T) {
	f, service := newSelectedTCPInlineScopeFixture(t)
	listScopeOperation(t, f.a, func(ctx context.Context) {
		source, err := f.a.ReviewXrayListRuntimeSource(ctx, f.scope, service.ID, f.adapter)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		prepared, err := source.prepare(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.close()
		input := (&DefaultRouteExecutor{app: f.a}).input(prepared.compilation, source.expected)
		// Runtime and journal both retain the ordinary serialized plan image.
		plan := defaultRouteClonePlan(dataplane.Plan{Routes: input.Routes, LAN: prepared.compilation.LAN(), NetworkProfileID: input.NetworkProfileID})
		_, started, finished := xrayAssemblySourceCAS(t, source)
		if err := source.acceptCommitted(ctx, started, finished); err != nil {
			t.Fatal(err)
		}
		cfg := f.a.Store.Get()
		current := selectedRoute(cfg.AppliedServices[service.ID])
		if len(plan.Routes) != 1 || plan.Routes[0].ServiceID == service.ID || plan.Routes[0].LogicalServiceID != service.ID ||
			reflect.DeepEqual(cfg.AppliedServices[service.ID].Sources, plan.Routes[0].Sources) {
			t.Fatal("fixture lost the actual synthetic-ID/configured-scope regression")
		}
		for _, probe := range []string{"healthy-round-1", "reserve-round", "healthy-round-2"} {
			f.record(t, "xray", probe, time.Now().UTC())
			if !autonomyManagedXrayCompiledMatches(plan, prepared.compilation, source.frozen, current) {
				t.Fatal("actual compiled healthy scope lost logical service", probe)
			}
		}
		for _, change := range []string{"logical-ID", "selected", "source", "destination", "ingress", "negative", "WAN", "generation", "probe"} {
			t.Run(change, func(t *testing.T) {
				changed := defaultRouteClonePlan(plan)
				switch change {
				case "logical-ID":
					changed.Routes[0].LogicalServiceID = "foreign"
				case "selected":
					changed.Routes[0].Selected = "xray:node-foreign"
				case "source":
					changed.Routes[0].Sources = []string{"192.168.1.41/32"}
				case "destination":
					changed.Routes[0].CIDRs = []string{"9.9.9.0/24"}
				case "ingress":
					changed.Routes[0].Ingress = []string{"br1"}
				case "negative":
					changed.LAN.Ingress[0].ExcludedSources = []string{"192.168.1.41/32"}
				case "WAN":
					changed.NetworkProfileID = "wan-foreign"
				case "generation":
					changed.Routes[0].NetworkPolicyGeneration = "foreign"
				case "probe":
					changed.Routes[0].ProbeService.ProbeURL = "https://9.9.9.9/"
				}
				if autonomyManagedXrayCompiledMatches(changed, prepared.compilation, source.frozen, current) {
					t.Fatal("changed compiled scope accepted", change)
				}
			})
		}
	})
}

// Genuine App transaction/journal with explicit checker and adapter models.
// The legacy branch still checks its committed adapter; managed selection
// refuses missing original ownership before that legacy adapter can run.
func TestAutonomyManagedXrayHealthCannotFallBackToLegacyOwner(t *testing.T) {
	a, _, adapter := autonomousIntegrationFixture(t)
	a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return autofallbackResult(request, true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	if state := autonomyTestState(a); state.State != "applied" {
		t.Fatal("actual legacy fixture apply", state)
	}
	plan, exists, err := a.Dataplane.Committed()
	if err != nil || !exists {
		t.Fatal(err)
	}
	cfg := a.Store.Get()
	id := "my-independent-site"
	current := selectedRoute(cfg.AppliedServices[id])
	guardCalls := 0
	guard := func(context.Context) error { guardCalls++; return nil }
	adapter.calls = nil
	if err := a.checkAutonomyCommittedNodeHealth(context.Background(), cfg, plan, id, current, guard); err != nil || !reflect.DeepEqual(adapter.calls, []string{"health"}) || guardCalls < 2 {
		t.Fatal("legacy committed check/bookends changed", err, adapter.calls, guardCalls)
	}
	adapter.calls, guardCalls = nil, 0
	// Comparison-only selected image. It cannot manufacture a retained owner.
	cfg.AppliedNetworkPolicy = &config.NetworkPolicy{}
	if err := a.checkAutonomyCommittedNodeHealth(context.Background(), cfg, plan, id, "xray:node-missing", guard); !errors.Is(err, ErrXrayListSource) || len(adapter.calls) != 0 || guardCalls < 2 {
		t.Fatal("managed selection fell back or skipped closing guard", err, adapter.calls, guardCalls)
	}
	revoked := errors.New("original selected scope revoked")
	if err := a.checkAutonomyCommittedNodeHealth(context.Background(), cfg, plan, id, "xray:node-missing", func(context.Context) error { return revoked }); !errors.Is(err, revoked) || len(adapter.calls) != 0 {
		t.Fatal("revoked authority reached health", err, adapter.calls)
	}
}
