package app

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

type recoveryNFQWSAdapter struct{ nodeApplyAdapter }

func (*recoveryNFQWSAdapter) ID() string { return "nfqws2" }

func mixedNodeRecoveryFixture(t *testing.T) (*App, *nodeApplyAdapter, *recoveryNFQWSAdapter, *recoveryChecker, dataplane.Plan) {
	t.Helper()
	a, _, proxy, checker, previous := nodeRecoveryFixture(t)
	nfqws := &recoveryNFQWSAdapter{}
	if err := a.Dataplane.Register(nfqws); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.UpdateService("telegram", a.Store.Get().AppliedServices["telegram"]); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	previous.Revision = a.Store.Get().AppliedRevision
	previous.Adapters = []string{"nfqws2", "sing-box"}
	previous.Routes = append(previous.Routes, dataplane.Route{ServiceID: "youtube", ServiceName: "YouTube", Selected: "nfqws2", Resolved: "nfqws2", Domains: []string{"youtube.com"}, ProbeURL: "https://youtube.com/"})
	if err := a.Dataplane.Record(previous); err != nil {
		t.Fatal(err)
	}
	options := a.nodeReviews.options()
	a.nodeReviews.options = func() []routecatalog.Option {
		return append(options, routecatalog.Option{ID: "nfqws2", Installed: true, Configured: true, Running: true, Selectable: true})
	}
	a.DataplaneHost = func() dataplane.HostState {
		return dataplane.HostState{IPCommand: true, TUN: true, SingBox: true, IPTables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true}
	}
	return a, proxy, nfqws, checker, previous
}

func TestMixedNodeRecoveryPreservesFullPlanAndPendingFiles(t *testing.T) {
	a, proxy, nfqws, checker, previous := mixedNodeRecoveryFixture(t)
	if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "direct", Sources: []string{"192.168.1.77/32"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.UpdateService("youtube", config.ServiceState{Enabled: false, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	a.EngineConfigs = engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
	if _, err := a.EngineConfigs.Stage("nfqws2", "user-list", "pending.example\n"); err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	draft, err := a.EngineConfigs.ReadExpert("nfqws2", "user-list")
	if err != nil {
		t.Fatal(err)
	}
	a.nodeRecoveryRound(context.Background(), time.Now())
	current, exists, err := a.Dataplane.Committed()
	if err != nil || !exists || a.nodeRecoverySnapshot().State != "recovered" {
		t.Fatalf("recovery: %+v, %v", a.nodeRecoverySnapshot(), err)
	}
	if !reflect.DeepEqual(current.Routes, previous.Routes) || !reflect.DeepEqual(current.Adapters, previous.Adapters) || len(current.EngineDrafts) != 0 || len(current.RetiringAdapters) != 0 || current.NetworkProfileID != recoveryProfile || current.Revision != before.AppliedRevision {
		t.Fatal("changed recovered targets, adapters, devices or draft scope")
	}
	afterDraft, err := a.EngineConfigs.ReadExpert("nfqws2", "user-list")
	if err != nil || !reflect.DeepEqual(draft, afterDraft) || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("recovery consumed pending settings")
	}
	if len(checker.requests) != 1 || checker.requests[0].Service.ID != "telegram" {
		t.Fatal("NFQWS2 was checked as a proxy node")
	}
	for _, calls := range [][]string{proxy.calls, nfqws.calls} {
		if strings.Join(calls, ",") != "snapshot,stage,validate,canary,activate,health,commit" {
			t.Fatalf("full pipeline not run: %v", calls)
		}
	}
	count := len(proxy.calls)
	a.nodeRecoveryRound(context.Background(), time.Now().Add(time.Minute))
	if len(proxy.calls) != count || len(checker.requests) != 1 {
		t.Fatal("recovered network reapplied unnecessarily")
	}
}

func TestMixedNodeRecoveryDoesNotPartiallyPromote(t *testing.T) {
	for _, failure := range []string{"node-check", "nfqws-health", "proxy-health", "catalog-before", "catalog-during"} {
		t.Run(failure, func(t *testing.T) {
			a, proxy, nfqws, checker, previous := mixedNodeRecoveryFixture(t)
			before := a.Store.Get()
			if failure == "node-check" {
				checker.fail = true
			}
			if failure == "catalog-before" {
				a.Catalog.Services[1].Domains = []string{"changed.example"}
			}
			checker.hook = func(context.Context, dataplane.NodeCheckRequest) {
				if failure == "catalog-during" {
					a.Catalog.Services[1].Domains = []string{"changed.example"}
				}
			}
			if failure == "nfqws-health" {
				nfqws.after = func(phase string) error {
					if phase == "health" {
						return errors.New("failed local health")
					}
					return nil
				}
			}
			if failure == "proxy-health" {
				proxy.after = func(phase string) error {
					if phase == "health" {
						return errors.New("failed proxy health")
					}
					return nil
				}
			}
			a.nodeRecoveryRound(context.Background(), time.Now())
			current, _, _ := a.Dataplane.Committed()
			if !sameNodeRecoveryPlan(previous, current) || !reflect.DeepEqual(before, a.Store.Get()) || a.nodeRecoverySnapshot().State == "recovered" {
				t.Fatal("partial recovery promoted or changed settings")
			}
			for _, calls := range [][]string{proxy.calls, nfqws.calls} {
				if strings.HasSuffix(failure, "health") {
					if !strings.Contains(strings.Join(calls, ","), "rollback") {
						t.Fatalf("missing full rollback: %v", calls)
					}
				} else if len(calls) != 0 {
					t.Fatalf("unreviewed/failed targets reached transaction: %v", calls)
				}
			}
		})
	}
}

func TestNodeRecoveryAdapterBoundary(t *testing.T) {
	for _, tc := range []struct {
		name             string
		routes, adapters []string
		ok               bool
	}{
		{"nodes", []string{"sing-box:node-a"}, []string{"sing-box"}, true},
		{"mixed", []string{"nfqws2", "sing-box:node-a"}, []string{"nfqws2", "sing-box"}, true},
		{"nfqws-only", []string{"nfqws2"}, []string{"nfqws2"}, false},
		{"unsupported", []string{"usque", "sing-box:node-a"}, []string{"usque", "sing-box"}, false},
		{"missing", []string{"nfqws2", "sing-box:node-a"}, []string{"sing-box"}, false},
		{"duplicate", []string{"nfqws2", "sing-box:node-a"}, []string{"sing-box", "sing-box"}, false},
		{"unrelated", []string{"sing-box:node-a"}, []string{"sing-box", "nfqws2"}, false},
		{"group-unresolved", []string{"sing-box:group-a"}, []string{"sing-box"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := dataplane.Plan{Adapters: tc.adapters}
			for _, r := range tc.routes {
				p.Routes = append(p.Routes, dataplane.Route{Resolved: r})
			}
			if nodeRecoveryAdaptersSupported(p) != tc.ok {
				t.Fatal("incorrect boundary")
			}
		})
	}
}
