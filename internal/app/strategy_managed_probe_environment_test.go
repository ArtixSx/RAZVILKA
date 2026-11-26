package app

import (
	"context"
	"net/netip"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

func strategyProbeEnvironmentFixture(t *testing.T) *managedStrategyProbeEnvironment {
	t.Helper()
	a := managedNFQInitialControlFixture(t)
	service := catalog.Service{ID: "video", ProbeURL: "https://example.com/probe", Domains: []string{"example.com"}}
	a.Catalog = catalog.Catalog{Services: []catalog.Service{service}}
	criteria, err := strategylab.ManagedProbeCriteriaDigest(service)
	if err != nil {
		t.Fatal(err)
	}
	r := &managedStrategyProbeEnvironment{app: a, store: a.Store, components: a.Components, expected: a.Store.Get(), catalog: applyReviewHash(a.Catalog), service: service, networkID: "wan-0123456789ab", fresh: stableNodeProfile,
		scope: strategylab.CandidateProbeScope{Target: strategylab.ProbeTarget{ServiceID: service.ID, ProbeURL: service.ProbeURL, Protocol: "tcp", IPFamily: "ipv4"}, Address: netip.MustParseAddr("93.184.216.34"), CriteriaDigest: criteria}}
	r.self = r
	return r
}

func TestManagedStrategyProbeEnvironmentExcludesExactResourceAndClosesObservations(t *testing.T) {
	for _, negative := range []config.ResourceMatch{{Kind: "service", Value: "video"}, {Kind: "exact", Value: "example.com"}, {Kind: "cidr", Value: "93.184.216.0/24"}} {
		t.Run(negative.Kind, func(t *testing.T) {
			r := strategyProbeEnvironmentFixture(t)
			if err := r.sourceCurrent(context.Background()); err != nil {
				t.Fatal(err)
			}
			manual := []config.ResourceMatch{negative}
			var err error
			r.expected, err = r.store.UpdateResourceExclusions(context.Background(), r.expected, &manual, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.sourceCurrent(context.Background()); err == nil {
				t.Fatal("excluded resource accepted")
			}
		})
	}
	for _, mutation := range []string{"wan", "catalog", "store", "cancel"} {
		t.Run(mutation, func(t *testing.T) {
			r := strategyProbeEnvironmentFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			r.fresh = func(context.Context) (string, error) {
				calls++
				_ = r.store.Get() // No Store lock may be held around this observer.
				if calls == 2 {
					switch mutation {
					case "wan":
						return "wan-abcdefabcdef", nil
					case "catalog":
						r.app.Catalog.Services[0].ProbeURL = "https://example.com/changed"
					case "store":
						if err := r.store.UpdateService("video", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
							t.Fatal(err)
						}
					case "cancel":
						cancel()
					}
				}
				return r.networkID, nil
			}
			if err := r.sourceCurrent(ctx); err == nil {
				t.Fatal("late environment drift accepted")
			}
		})
	}
}
