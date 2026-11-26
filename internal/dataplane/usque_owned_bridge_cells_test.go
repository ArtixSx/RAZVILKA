package dataplane

import (
	"context"
	"strconv"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

func TestUSQUEOwnedBridgeSeveralPolicyCellsKeepOneFullServiceProbe(t *testing.T) {
	f := usqueOwnedBridgeNewFixture(t, usqueTransport{})
	first := f.plan.Routes[0]
	first.Sources = []string{"192.168.1.10/32"}
	second := first
	second.Sources = []string{"192.168.1.11/32"}
	f.plan.Routes = []Route{first, second}
	f.services = append(f.services, copyProxyPredicateService(f.services[0]))
	calls := 0
	f.a.ownedUSQUEProbe = func(ctx context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
		calls++
		if len(options.Network.Services) != 1 || options.Network.Services[0].ID != f.services[0].ID {
			t.Fatal("identical catalog semantics became multiple or synthetic grades")
		}
		probe := options.Network.Services[0]
		if err := probe.Validator(usqueOwnedBridgeAcceptedResponse(probe.URL)); err != nil {
			t.Fatal("full predicate was lost while merging cells", err)
		}
		return usqueOwnedBridgeProof(options), nil
	}
	proof, err := f.a.probeOwnedUSQUECandidate(f.ctx, f.plan, f.spec, f.address, f.services)
	if err != nil || calls != 1 || len(proof.ConfirmedRoutes) != 1 || proof.ConfirmedRoutes[0] != f.services[0].ID ||
		len(f.plan.Routes) != 2 || f.plan.Routes[0].Sources[0] != "192.168.1.10/32" || f.plan.Routes[1].Sources[0] != "192.168.1.11/32" {
		t.Fatal("semantic dedup rewrote policy cells or producer grades", err)
	}
}

func TestUSQUEOwnedBridgeDuplicateServiceRequiresIdenticalFrozenPredicate(t *testing.T) {
	for _, mode := range []string{"body", "status", "url", "missing-freeze"} {
		t.Run(mode, func(t *testing.T) {
			f := usqueOwnedBridgeNewFixture(t, usqueTransport{})
			second := f.plan.Routes[0]
			service := copyProxyPredicateService(f.services[0])
			switch mode {
			case "body":
				service.Probes[0].Expect.BodyContains = []string{"different required semantics"}
			case "status":
				service.Probes[0].Expect.StatusCodes = []int{201}
			case "url":
				service.ProbeURL = "https://example.com/different"
				service.Probes[0].URL = service.ProbeURL
				second.ProbeURL = service.ProbeURL
			}
			second.ProbeService = &service
			if mode == "missing-freeze" {
				second.ProbeService = nil
			}
			f.plan.Routes = append(f.plan.Routes, second)
			f.services = append(f.services, service)
			f.a.ownedUSQUEProbe = func(context.Context, usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
				t.Fatal("conflicting frozen service cells reached the producer")
				return usquediag.OwnedRuntimeEvidence{}, nil
			}
			if _, err := f.a.probeOwnedUSQUECandidate(f.ctx, f.plan, f.spec, f.address, f.services); err == nil {
				t.Fatal("conflicting predicates shared one semantic proof")
			}
		})
	}
}

func TestUSQUEOwnedBridgeCellAndDistinctProbeBudgets(t *testing.T) {
	f := usqueOwnedBridgeNewFixture(t, usqueTransport{})
	for _, cells := range []int{64, 65} {
		plan := f.plan
		plan.Routes = nil
		var services []catalog.Service
		for range cells {
			plan.Routes = append(plan.Routes, f.plan.Routes[0])
			services = append(services, f.services[0])
		}
		probes, err := ownedUSQUECandidateServices(f.ctx, plan, services)
		if cells == 64 && (err != nil || len(probes) != 1) || cells == 65 && err == nil {
			t.Fatal("raw cell budget was lost during semantic dedup", cells, len(probes), err)
		}
	}
	for _, distinct := range []int{8, 9} {
		plan := f.plan
		plan.Routes = nil
		var services []catalog.Service
		for i := range distinct {
			service := copyProxyPredicateService(f.services[0])
			service.ID = "service-" + strconv.Itoa(i)
			route := f.plan.Routes[0]
			route.ServiceID, route.ProbeService = service.ID, &service
			plan.Routes = append(plan.Routes, route)
			services = append(services, service)
		}
		probes, err := ownedUSQUECandidateServices(f.ctx, plan, services)
		if distinct == 8 && (err != nil || len(probes) != 8) || distinct == 9 && err == nil {
			t.Fatal("distinct semantic probe budget changed", distinct, len(probes), err)
		}
	}
}
