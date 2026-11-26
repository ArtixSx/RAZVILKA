package app

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

func TestNFQWS2StarterRepairGuardsOwnedBudgetAndPolicy(t *testing.T) {
	for _, scenario := range []string{"unowned", "disallowed", "budget"} {
		t.Run(scenario, func(t *testing.T) {
			a, model, probes := autoNFQFirstStartFixture(t)
			const service = "discord"
			applied := runAutoNFQDispatcher(t, a, service, func() bool { return true }, nil)
			if applied.State != "applied" {
				t.Fatal(applied)
			}
			before := a.Store.Get()
			policy := a.autonomyPolicy()
			if !a.autonomyRuntime(policy.Revision, service, applied) {
				t.Fatal("persist applied test state")
			}
			// The installed component can be unavailable even though its last
			// applied plan still exists. This model is not a stock native owner.
			a.nodeReviews.options = func() []routecatalog.Option {
				return []routecatalog.Option{{ID: "nfqws2", Installed: true, Configured: true}}
			}
			model.calls = nil
			want := map[string]string{"unowned": "component-stopped", "disallowed": "capability-refused", "budget": "rate-limited"}[scenario]
			got := runAutoNFQDispatcher(t, a, service, func() bool {
				t.Error("recovery entered the first-apply path")
				return false
			}, func(p *autonomy.Policy, _ *autonomy.Service, r *autonomy.Runtime, _ *context.Context) {
				if scenario == "disallowed" {
					p.PreferredRoutes = []string{"xray"}
				}
				if scenario == "budget" {
					r.Switches = slices.Repeat([]time.Time{time.Now().Add(-10 * time.Minute)}, p.MaxSwitchesPerHour)
				}
			})
			if got.State != want || len(model.calls) != 0 || *probes != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatalf("%s: state=%+v calls=%v probes=%d", scenario, got, model.calls, *probes)
			}
			if scenario == "unowned" && (!slices.Equal(got.Switches, applied.Switches) || !strings.Contains(got.Message, "перезапуск") || got.NextCheck.Before(time.Now().Add(55*time.Second))) {
				t.Fatalf("early refusal did not return the switch reservation or wait before retry: %+v", got)
			}
		})
	}
}

func TestNFQWS2StarterRepairRequiresSharedConsentAndOneRequester(t *testing.T) {
	for _, scenario := range []string{"both-approved", "secondary-cannot-request", "stale-peer", "manual-peer", "changed-peer-scope", "excluded-peer", "new-address-exclusion", "changed-excluded-domains", "revoked-after-capture"} {
		t.Run(scenario, func(t *testing.T) {
			a, model, probes := autoNFQFirstStartFixture(t)
			policy := a.autonomyPolicy()
			if scenario == "changed-excluded-domains" {
				manual := []config.ResourceMatch{{Kind: "service", Value: "youtube"}}
				if _, err := a.Store.UpdateResourceExclusions(t.Context(), a.Store.Get(), &manual, nil); err != nil {
					t.Fatal(err)
				}
			}
			for _, id := range []string{"discord", "speedtest"} {
				state := runAutoNFQDispatcher(t, a, id, func() bool { return true }, nil)
				if state.State != "applied" || !a.autonomyRuntime(policy.Revision, id, state) {
					t.Fatal("first apply failed", id, state)
				}
			}
			a.nodeReviews.options = func() []routecatalog.Option {
				return []routecatalog.Option{{ID: "nfqws2", Installed: true, Configured: true}}
			}
			primary, want := "discord", "component-stopped"
			switch scenario {
			case "secondary-cannot-request":
				primary, want = "speedtest", "unconfirmed"
			case "stale-peer":
				for i, service := range a.Catalog.Services {
					if service.ID == "speedtest" {
						a.Catalog.Services[i].ProbeURL = "https://stale.example/"
					}
				}
				want = "component-unavailable"
			case "excluded-peer":
				manual := []config.ResourceMatch{{Kind: "service", Value: "speedtest"}}
				if _, err := a.Store.UpdateResourceExclusions(context.Background(), a.Store.Get(), &manual, nil); err != nil {
					t.Fatal(err)
				}
				want = "paused"
			case "new-address-exclusion":
				manual := []config.ResourceMatch{{Kind: "cidr", Value: "203.0.113.0/24"}}
				if _, err := a.Store.UpdateResourceExclusions(t.Context(), a.Store.Get(), &manual, nil); err != nil {
					t.Fatal(err)
				}
				want = "paused"
			case "changed-excluded-domains":
				for i, service := range a.Catalog.Services {
					if service.ID == "youtube" {
						a.Catalog.Services[i].Domains = append(slices.Clone(service.Domains), "new-excluded.example")
					}
				}
				want = "paused"
			case "revoked-after-capture":
				reads, currentProfile := 0, a.FreshProfile
				a.FreshProfile = func(ctx context.Context) (string, error) {
					reads++
					if reads == 2 {
						// The second WAN read is the repair guard, after it
						// captured the peers and before any repair can run.
						a.autonomy.mu.Lock()
						old := a.autonomy.doc.Services["speedtest"]
						a.autonomy.mu.Unlock()
						if _, ok := a.updateAutonomyService(ctx, policy, old, func(peer *autonomy.Service) { peer.Enabled = false }); !ok {
							t.Error("could not revoke captured peer")
						}
					}
					return currentProfile(ctx)
				}
				want = "paused"
			case "manual-peer", "changed-peer-scope":
				a.autonomy.mu.Lock()
				old := a.autonomy.doc.Services["speedtest"]
				a.autonomy.mu.Unlock()
				if _, ok := a.updateAutonomyService(context.Background(), policy, old, func(peer *autonomy.Service) {
					if scenario == "manual-peer" {
						peer.ExpectedRoute = "nfqws2"
					} else {
						peer.AllLAN = false
						peer.Sources = []string{"192.168.1.2/32"}
					}
				}); !ok {
					t.Fatal("could not change peer intent")
				}
				want = "component-unavailable"
			}
			before := a.Store.Get()
			model.calls = nil
			got := runAutoNFQDispatcher(t, a, primary, func() bool {
				t.Error("shared restart entered the first-apply path")
				return false
			}, nil)
			if got.State != want || len(got.Switches) != 1 || len(model.calls) != 0 || *probes != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatalf("%s: state=%+v calls=%v probes=%d", scenario, got, model.calls, *probes)
			}
		})
	}
}
