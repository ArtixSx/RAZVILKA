package app

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
)

func autoNFQFirstStartFixture(t *testing.T) (*App, *nfqDefinitionRuntimeModel, *int) {
	t.Helper()
	a, model, probes := starterFirstStartFixture(t)
	a.Catalog.Services = append(a.Catalog.Services, starterService(t, "speedtest"))
	for _, id := range []string{"youtube", "discord", "speedtest"} {
		if err := a.Store.UpdateService(id, config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
			t.Fatal(err)
		}
		if id == "speedtest" {
			if err := a.inheritAutonomyService(context.Background(), id); err != nil {
				t.Fatal(err)
			}
		}
		a.autonomy.mu.Lock()
		s := a.autonomy.doc.Services[id]
		a.autonomy.mu.Unlock()
		if _, ok := a.updateAutonomyService(context.Background(), a.autonomyPolicy(), s, func(next *autonomy.Service) {
			next.ExpectedRoute = "auto"
			next.DraftFingerprint = autonomyDraftFingerprint(a.Store.Get().Services[id])
		}); !ok {
			t.Fatal("could not enroll AUTO draft")
		}
	}
	return a, model, probes
}

func runAutoNFQDispatcher(t *testing.T, a *App, id string, review func() bool, mutate func(*autonomy.Policy, *autonomy.Service, *autonomy.Runtime, *context.Context)) autonomy.Runtime {
	t.Helper()
	ctx, release, err := a.privateExclusiveOperation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	p := a.autonomyPolicy()
	a.autonomy.mu.Lock()
	s, r := a.autonomy.doc.Services[id], a.autonomy.doc.Runtime[id].Clone()
	a.autonomy.mu.Unlock()
	if mutate != nil {
		mutate(&p, &s, &r, &ctx)
	}
	return a.runAutonomyServiceWithNFQWS2Review(ctx, p, s, r, time.Now(), review)
}

func TestAutonomyAutoNFQFirstStartDispatcherInstallsMissingDomainsBeforeProbe(t *testing.T) {
	a, model, probes := autoNFQFirstStartFixture(t)
	for index, id := range []string{"youtube", "discord", "speedtest"} {
		model.calls = nil
		before := a.Store.Get()
		r := runAutoNFQDispatcher(t, a, id, func() bool { return true }, func(p *autonomy.Policy, _ *autonomy.Service, _ *autonomy.Runtime, _ *context.Context) {
			// A source preference cannot create a node phase for domain services.
			p.PreferredSourceIDs = []string{"manual"}
		})
		plan, exists, err := a.Dataplane.Committed()
		if err != nil || !exists || r.State != "applied" || *probes != 0 || !slices.Contains(model.calls, "health") || !slices.Contains(model.calls, "commit") {
			t.Fatalf("AUTO required impossible pre-PASS or skipped transactional apply: %s %+v calls=%v probes=%d err=%v", id, r, model.calls, *probes, err)
		}
		after := a.Store.Get()
		if len(plan.Routes) != index+1 || !committedServiceCurrent(plan, starterService(t, id)) || selectedRoute(after.Services[id]) != "nfqws2" || len(r.Switches) != 1 || !r.CheckedAt.IsZero() {
			t.Fatal("AUTO lost prior domains or fabricated proof", r)
		}
		for other, draft := range before.Services {
			if other != id && !reflect.DeepEqual(draft, after.Services[other]) {
				t.Fatal("AUTO changed another service draft", other)
			}
		}
		for _, route := range plan.Routes {
			if route.Resolved != "nfqws2" || len(route.Sources) != 0 || len(route.CIDRs) != 0 {
				t.Fatal("AUTO widened domain authority", route)
			}
		}
	}
}

func TestAutonomyAutoNFQFirstStartDispatcherKeepsAdmissionGuards(t *testing.T) {
	for _, refusal := range []string{"foreign-profile", "not-preferred", "selected", "mixed-cidr", "unreviewed", "revoked", "stop", "cancel", "budget", "already-applied"} {
		t.Run(refusal, func(t *testing.T) {
			a, model, probes := autoNFQFirstStartFixture(t)
			model.active = true
			if refusal == "already-applied" {
				if r := runAutoNFQDispatcher(t, a, "discord", func() bool { return true }, nil); r.State != "applied" {
					t.Fatal(r)
				}
			}
			if refusal == "stop" {
				if r := runAutoNFQDispatcher(t, a, "youtube", func() bool { return true }, nil); r.State != "applied" {
					t.Fatal(r)
				}
				if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"youtube": "nfqws2"}, a.Store.Get().Revision); err != nil {
					t.Fatal(err)
				}
			}
			if refusal == "mixed-cidr" || refusal == "unreviewed" {
				for i := range a.Catalog.Services {
					if a.Catalog.Services[i].ID == "discord" {
						if refusal == "mixed-cidr" {
							a.Catalog.Services[i].CIDRs = []string{"203.0.113.0/24"}
						} else {
							a.Catalog.Services[i].Domains = append(a.Catalog.Services[i].Domains, "unreviewed.example")
						}
					}
				}
			}
			if refusal == "selected" || refusal == "mixed-cidr" || refusal == "unreviewed" {
				a.autonomy.mu.Lock()
				s := a.autonomy.doc.Services["discord"]
				a.autonomy.mu.Unlock()
				if _, ok := a.updateAutonomyService(context.Background(), a.autonomyPolicy(), s, func(next *autonomy.Service) {
					service, _ := a.autonomyService("discord")
					next.Definition = autonomyDefinition(service)
					if refusal == "selected" {
						next.AllLAN, next.Sources = false, []string{"192.168.1.50/32"}
					}
				}); !ok {
					t.Fatal("could not persist reviewed test scope")
				}
			}
			before := a.Store.Get()
			model.calls = nil
			r := runAutoNFQDispatcher(t, a, "discord", func() bool { return refusal != "foreign-profile" }, func(p *autonomy.Policy, s *autonomy.Service, r *autonomy.Runtime, ctx *context.Context) {
				switch refusal {
				case "not-preferred":
					p.PreferredRoutes = []string{"sing-box"}
				case "revoked":
					a.autonomy.mu.Lock()
					changed := a.autonomy.doc.Services[s.ID]
					changed.Enabled = false
					a.autonomy.doc.Services[s.ID] = changed
					a.autonomy.mu.Unlock()
				case "cancel":
					canceled, cancel := context.WithCancel(*ctx)
					cancel()
					*ctx = canceled
				case "budget":
					for i := 0; i < p.MaxSwitchesPerHour; i++ {
						r.Switches = append(r.Switches, time.Now().Add(-time.Minute))
					}
				}
			})
			if r.State == "applied" || len(model.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("AUTO bypassed admission or changed runtime", r, model.calls)
			}
			if refusal == "foreign-profile" && *probes != 1 {
				t.Fatal("foreign running profile did not retain ordinary probe", r, *probes)
			}
		})
	}
}

func TestAutonomyAutoNFQFirstStartDispatcherRechecksRevisionAfterAdvisory(t *testing.T) {
	a, model, probes := autoNFQFirstStartFixture(t)
	reviews := 0
	r := runAutoNFQDispatcher(t, a, "discord", func() bool {
		reviews++
		if reviews == 1 {
			if err := a.Store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
				t.Fatal(err)
			}
		}
		return true
	}, nil)
	if r.State != "paused" || len(model.calls) != 0 || *probes != 0 || len(r.Switches) != 0 || selectedRoute(a.Store.Get().Services["discord"]) != "auto" {
		t.Fatal("stale advisory bypassed configuration fence", r, model.calls, *probes)
	}
}
