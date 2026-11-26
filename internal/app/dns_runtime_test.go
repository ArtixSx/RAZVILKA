package app

import (
	"context"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

func dnsRuntimeFixture(t *testing.T) *App {
	t.Helper()
	a := genericReviewFixture(t)
	a.Catalog.Services[0].ProbeURL = "https://telegram.org/"
	a.DNS, _ = dnscontrol.New("")
	if err := a.DNS.SetServiceDraft("telegram", "private"); err != nil {
		t.Fatal(err)
	}
	a.FreshProfile = func(context.Context) (string, error) { return "wan-0123456789ab", nil }
	a.Dataplane = dataplane.New(t.TempDir())
	a.Dataplane.FreshProfile = a.FreshProfile
	adapter := &dnsReviewAdapter{dns: a.DNS, nodeApplyAdapter: &nodeApplyAdapter{}}
	if err := a.Dataplane.Register(adapter); err != nil {
		t.Fatal(err)
	}
	identity, _ := a.DNS.ScopedProfileIdentity("private")
	policy := &dataplane.ScopedDNSPlan{Listener: "192.168.1.1:10553", Ingress: "br0", Probe: catalog.Probe{ID: "web", Label: "Web", URL: "https://telegram.org/", Required: true}, Bindings: []dataplane.ScopedDNSBinding{{ServiceID: "telegram", Client: "192.168.1.40", Domain: "telegram.org", ProfileID: "private", ProfileDigest: identity}}}
	p, err := a.buildDataplanePlanWithDNS(a.Store.Get(), nil, changeScopeRouting, "", &scopedDNSChange{Explicit: true, Policy: policy})
	if err != nil || !p.Ready {
		t.Fatalf("fixture plan: %v %+v", err, p.Blockers)
	}
	b, err := a.bindApplyReview(context.Background(), a.Store.Get(), p, changeScopeRouting, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := dataplane.WithReviewGuard(context.Background(), func(ctx context.Context) error { return b.guard(a, ctx) })
	if _, err := a.applyDataplane(ctx, p, func() (func() error, error) { return b.commit(a, ctx, changeScopeRouting) }); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestDNSRuntimeStopResumeKeepsAppliedProfileScopeAndEngineDraft(t *testing.T) {
	a := dnsRuntimeFixture(t)
	if err := a.DNS.SetDraft("security"); err != nil {
		t.Fatal(err)
	}
	if err := a.DNS.SetServiceDraft("telegram", "unfiltered"); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "direct", Sources: []string{"192.168.1.41/32"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.EngineConfigs.Stage("sing-box", "main", `{"log":{"level":"info"}}`); err != nil {
		t.Fatal(err)
	}
	wanted := a.Store.Get().Services
	for _, action := range []string{"stop", "resume"} {
		out := a.executeServiceRuntime(context.Background(), action, a.Store.Get().Revision)
		if out.Code != "" || !out.LiveApplied {
			t.Fatalf("%s failed: %+v", action, out)
		}
		cfg := a.Store.Get()
		if cfg.ServiceControl.Stopped != (action == "stop") || !reflect.DeepEqual(cfg.Services, wanted) {
			t.Fatal("runtime changed desired services")
		}
		if a.DNS.VerifyServiceSelection("telegram", "private") != nil || a.DNS.Snapshot().ServiceDrafts["telegram"] != "unfiltered" {
			t.Fatal("runtime consumed pending DNS")
		}
		if a.DNS.Snapshot().Draft.ProfileID != "security" {
			t.Fatal("runtime consumed global DNS draft")
		}
		v, err := a.EngineConfigs.ReadExpert("sing-box", "main")
		if err != nil || v.Source != "staged" {
			t.Fatal("runtime consumed engine draft", err)
		}
		p, exists, err := a.Dataplane.Committed()
		if err != nil || !exists {
			t.Fatal(err)
		}
		if action == "stop" && (p.DNS != nil || !p.SuspendDNS || len(p.Routes) != 0) {
			t.Fatal("DNS not suspended")
		}
		if action == "stop" {
			if _, err := a.buildDataplanePlanForScope(cfg, nil, changeScopeEngine, "sing-box"); err == nil {
				t.Fatal("unrelated apply can discard suspended DNS snapshot")
			}
		}
		if action == "resume" && (p.DNS == nil || p.DNS.Bindings[0].Client != "192.168.1.40" || p.DNS.Bindings[0].ProfileID != "private" || len(p.EngineDrafts) != 0 || cfg.AppliedServices["telegram"].Sources[0] != "192.168.1.40/32") {
			t.Fatal("resume broadened scope or replaced saved DNS")
		}
	}
}

func TestDNSPlanRetentionAndScopeChangesRequireReview(t *testing.T) {
	for _, change := range []string{"retain", "client", "route", "scenario", "domain", "disable"} {
		t.Run(change, func(t *testing.T) {
			a := dnsRuntimeFixture(t)
			cfg := a.Store.Get()
			scope := changeScopeRouting
			switch change {
			case "client":
				state := cfg.Services["telegram"]
				state.Sources = []string{"192.168.1.41/32"}
				cfg.Services["telegram"] = state
			case "route":
				state := cfg.Services["telegram"]
				state.Route = "usque"
				cfg.Services["telegram"] = state
			case "scenario":
				a.Catalog.Services[0].Probes = []catalog.Probe{{ID: "web", Label: "Web", URL: "https://telegram.org/", Required: true, Expect: catalog.ProbeExpectation{BodyContains: []string{"new scenario"}}}}
			case "domain":
				a.Catalog.Services[0].Domains = append(a.Catalog.Services[0].Domains, "extra.telegram.org")
			case "disable":
				state := cfg.Services["telegram"]
				state.Enabled = false
				cfg.Services["telegram"] = state
			}
			p, err := a.buildDataplanePlanForScope(cfg, nil, scope, "")
			if change == "retain" {
				if err != nil || p.DNS == nil || !p.Ready {
					t.Fatal("unrelated apply dropped DNS", err)
				}
			} else if change == "disable" {
				if err != nil || p.DNS != nil || len(p.RetiringAdapters) != 1 || p.RetiringAdapters[0] != "dns-scoped" || p.SuspendDNS {
					t.Fatal("disabled service left DNS", err)
				}
			} else if err == nil {
				t.Fatal("changed DNS scope/scenario accepted")
			}
		})
	}
}
