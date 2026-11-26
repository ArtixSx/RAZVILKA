package app

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

func TestNodeGroupPlanPreservesUnrelatedSingBoxDraftInEveryRoutingScope(t *testing.T) {
	a, id, _ := nodeApplyFixture(t)
	group, err := a.Nodes.CreateGroup(context.Background(), "Fallback", "fallback", []string{id}, id, time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a.EngineConfigs = engineconfig.New(filepath.Join(t.TempDir(), "stage"), t.TempDir())
	const draft = "{\n  \"outbounds\": []\n}\n"
	if _, err := a.EngineConfigs.Stage("sing-box", "main", draft); err != nil {
		t.Fatal(err)
	}
	if _, err := a.EngineConfigs.Stage("nfqws2", "main", "NFQWS_ARGS=\"--debug\"\n"); err != nil {
		t.Fatal(err)
	}
	cfg := a.Store.Get()
	cfg.Services["telegram"] = config.ServiceState{Enabled: true, Route: "sing-box:" + group.ID, Sources: []string{"192.168.1.40/32"}}
	cfg.Services["youtube"] = config.ServiceState{Enabled: true, Route: "nfqws2"}
	cfg.AppliedServices = cfg.Services
	options := append(a.nodeRouteOptions(), routecatalog.Option{ID: "sing-box:" + group.ID, Installed: true, Configured: true, Selectable: true, Services: []string{"telegram"}}, routecatalog.Option{ID: "nfqws2", Installed: true, Configured: true, Selectable: true})
	before := a.Store.Get()
	for _, scope := range []changeScope{changeScopeAll, changeScopeRouting, changeScopeServices, changeScopeDevices, changeScopeEngine} {
		plan, err := a.buildDataplanePlanForScope(cfg, options, scope, "sing-box")
		if err != nil {
			t.Fatalf("%s: %v", scope, err)
		}
		if plan.Routes[0].Selected != "sing-box:"+group.ID || plan.Routes[0].Resolved != "sing-box:"+id {
			t.Fatalf("%s lost exact group route", scope)
		}
		if scope == changeScopeEngine {
			blocked := false
			for _, b := range plan.Blockers {
				blocked = blocked || b.Code == "NODE_ROUTE_ENGINE_DRAFT"
			}
			if !blocked || plan.Ready {
				t.Fatal("explicit editor apply falsely claimed to apply unused draft")
			}
		} else {
			for _, ref := range plan.EngineDrafts {
				if ref == "sing-box/main" {
					t.Fatalf("%s consumed unrelated draft", scope)
				}
			}
			if scope != changeScopeDevices && !reflect.DeepEqual(plan.EngineDrafts, []string{"nfqws2/main"}) {
				t.Fatalf("%s changed another adapter draft: %v", scope, plan.EngineDrafts)
			}
		}
	}
	view, err := a.EngineConfigs.ReadExpert("sing-box", "main")
	if err != nil || view.Source != "staged" || view.Content != draft || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("plan mutated saved draft or configuration")
	}
}
