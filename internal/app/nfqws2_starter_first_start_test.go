package app

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

func starterFirstStartFixture(t *testing.T) (*App, *nfqDefinitionRuntimeModel, *int) {
	t.Helper()
	a := autonomyAPIFixture(t)
	a.Catalog = catalog.Catalog{Services: []catalog.Service{starterService(t, "youtube"), starterService(t, "discord")}}
	a.Dataplane = dataplane.New(filepath.Join(t.TempDir(), "dataplane"))
	a.FreshProfile, a.Dataplane.FreshProfile = stableNodeProfile, stableNodeProfile
	model := &nfqDefinitionRuntimeModel{serviceRuntimeAdapter: &serviceRuntimeAdapter{nodeApplyAdapter: &nodeApplyAdapter{}, name: "nfqws2"}}
	if err := a.Dataplane.Register(model); err != nil {
		t.Fatal(err)
	}
	a.DataplaneHost = func() dataplane.HostState {
		return dataplane.HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}
	}
	a.nodeReviews.options = func() []routecatalog.Option {
		return []routecatalog.Option{{ID: "direct", Installed: true, Configured: true, Selectable: true, Ready: true}, {ID: "nfqws2", Installed: true, Configured: true, Running: model.active, Selectable: true, Ready: true}}
	}
	probes := new(int)
	a.TestLab = testlab.NewRunner()
	a.RouteProber = autonomyResourceRouteProber(func(_ context.Context, service catalog.Service, route string) testlab.Result {
		*probes = *probes + 1
		return testlab.Result{ServiceID: service.ID, ServiceName: service.Name, ProbeURL: service.ProbeURL, Route: route, Status: "fail", CheckedAt: time.Now().UTC().Format(time.RFC3339), RouteConfirmed: true, EvidenceSource: "test-unconfigured-domain"}
	})
	for _, id := range []string{"youtube", "discord"} {
		if err := a.Store.UpdateService(id, config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
			t.Fatal(err)
		}
	}
	p := autonomy.Default()
	p.SetupComplete, p.Enabled, p.InheritNewServices, p.AllLAN = true, true, true, true
	p.DefaultSources, p.PreferredRoutes = nil, []string{"nfqws2"}
	p.Application.Mode, p.Components.Mode = "off", "off"
	w := httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": 0, "policy": p, "confirm": "SAVE_AUTONOMY", "release_safe_mode": true}))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, id := range []string{"youtube", "discord"} {
		if err := a.inheritAutonomyService(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	return a, model, probes
}

func runStarterProfileReview(t *testing.T, a *App, id string, review func() bool, mutate func(*autonomy.Policy, *autonomy.Service, *autonomy.Runtime, *catalog.Service, *config.Config, *context.Context)) autonomy.Runtime {
	t.Helper()
	ctx, release, err := a.privateExclusiveOperation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	p, cfg := a.autonomyPolicy(), a.Store.Get()
	a.autonomy.mu.Lock()
	s, r := a.autonomy.doc.Services[id], a.autonomy.doc.Runtime[id].Clone()
	a.autonomy.mu.Unlock()
	service, _ := a.autonomyService(id)
	if mutate != nil {
		mutate(&p, &s, &r, &service, &cfg, &ctx)
	}
	profile, err := stableNodeProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return a.runNFQWS2StarterWithProfileReview(ctx, p, s, r, service, cfg, profile, review)
}

func TestNFQWS2FirstStartThenUnappliedServiceUsesOrdinaryScopedApply(t *testing.T) {
	a, model, probes := starterFirstStartFixture(t)
	for index, id := range []string{"youtube", "discord"} {
		model.calls = nil
		before := a.Store.Get()
		r := runStarterProfileReview(t, a, id, func() bool { return true }, nil)
		plan, exists, err := a.Dataplane.Committed()
		if err != nil || !exists || r.State != "applied" || !slices.Contains(model.calls, "health") || !slices.Contains(model.calls, "commit") || *probes != 0 {
			t.Fatalf("unapplied service required impossible pre-PASS or skipped ordinary Apply: %s %+v calls=%v err=%v", id, r, model.calls, err)
		}
		if len(plan.Routes) != index+1 || !committedServiceCurrent(plan, starterService(t, id)) || !reflect.DeepEqual(a.Store.Get().Services, before.Services) || len(r.Switches) != 1 || !r.CheckedAt.IsZero() {
			t.Fatal("plan lost prior service, consumed edits, or fabricated a check timestamp")
		}
		for _, route := range plan.Routes {
			if route.Resolved != "nfqws2" || len(route.Sources) != 0 || len(route.CIDRs) != 0 {
				t.Fatal("profile scope widened")
			}
		}
		if !model.active || !model.committed {
			t.Fatal("Apply never activated/committed runtime")
		}
	}
}

func TestNFQWS2FirstStartReviewNeverBypassesAppliedOrForeignProfile(t *testing.T) {
	for _, applied := range []bool{false, true} {
		t.Run(map[bool]string{false: "foreign-running", true: "already-applied"}[applied], func(t *testing.T) {
			a, model, probes := starterFirstStartFixture(t)
			if applied {
				if r := runStarterProfileReview(t, a, "youtube", func() bool { return true }, nil); r.State != "applied" {
					t.Fatal(r)
				}
			} else {
				model.active = true
			}
			model.calls = nil
			reviews := 0
			r := runStarterProfileReview(t, a, "youtube", func() bool { reviews++; return false }, nil)
			if r.State == "applied" || len(model.calls) != 0 || *probes != 1 || applied && reviews != 0 {
				t.Fatal("ordinary path was bypassed without an eligible unapplied owned profile", r, reviews, *probes, model.calls)
			}
		})
	}
}

func TestNFQWS2FirstStartKeepsConsentStopBudgetAndClosedScope(t *testing.T) {
	for _, refusal := range []string{"revoked", "stopped", "cancel", "revision", "budget", "selected", "mixed-cidr"} {
		t.Run(refusal, func(t *testing.T) {
			a, model, probes := starterFirstStartFixture(t)
			before := a.Store.Get()
			r := runStarterProfileReview(t, a, "youtube", func() bool { return true }, func(p *autonomy.Policy, s *autonomy.Service, r *autonomy.Runtime, service *catalog.Service, cfg *config.Config, ctx *context.Context) {
				switch refusal {
				case "revoked":
					a.autonomy.mu.Lock()
					changed := a.autonomy.doc.Services[s.ID]
					changed.Enabled = false
					a.autonomy.doc.Services[s.ID] = changed
					a.autonomy.mu.Unlock()
				case "stopped":
					cfg.ServiceControl.Stopped = true
				case "cancel":
					canceled, cancel := context.WithCancel(*ctx)
					cancel()
					*ctx = canceled
				case "revision":
					cfg.Revision++
				case "budget":
					for i := 0; i < p.MaxSwitchesPerHour; i++ {
						r.Switches = append(r.Switches, time.Now().Add(-time.Minute))
					}
				case "selected":
					s.AllLAN = false
					s.Sources = []string{"192.168.1.50/32"}
				case "mixed-cidr":
					service.CIDRs = []string{"203.0.113.0/24"}
				}
			})
			if r.State == "applied" || len(model.calls) != 0 || *probes != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("refused profile entered Apply or changed config", r, model.calls)
			}
			if refusal != "budget" && len(r.Switches) != 0 {
				t.Fatal("refusal consumed apply budget")
			}
			if refusal == "mixed-cidr" && (r.State != "unsupported-scenario" || !strings.Contains(r.Message, "IP-сетями")) {
				t.Fatal("CIDR coverage was claimed", r)
			}
			if refusal == "selected" && r.State != "unsupported-scenario" {
				t.Fatal("device scope was offered a whole-LAN profile", r)
			}
		})
	}
}

func TestNFQWS2FirstStartAdvisoryReviewCannotOverrideCommittedStop(t *testing.T) {
	a, model, probes := starterFirstStartFixture(t)
	if r := runStarterProfileReview(t, a, "youtube", func() bool { return true }, nil); r.State != "applied" {
		t.Fatal(r)
	}
	// Model the configuration half of the already authorized runtime Stop.
	// Even a stale advisory profile read must not override this current state.
	if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"youtube": "nfqws2"}, a.Store.Get().Revision); err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	model.calls = nil
	r := runStarterProfileReview(t, a, "discord", func() bool { return true }, nil)
	if r.State == "applied" || len(model.calls) != 0 || *probes != 0 || !reflect.DeepEqual(before, a.Store.Get()) || len(r.Switches) != 0 {
		t.Fatal("advisory read overrode Stop or consumed apply budget", r, model.calls)
	}
}
