package app

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

func TestAutonomyUSQUECommittedHealthNeverUsesGenericRouteProber(t *testing.T) {
	a, _, _ := autonomousIntegrationFixture(t)
	s := setAutonomyUSQUEPolicy(t, a, true)
	p := a.autonomyPolicy()
	service, _ := a.autonomyService(s.ID)
	ctx, release, err := a.scopedRuntimeOperation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := a.Store.ApplyAutonomyRouteWithRollback(s.ID, "usque", s.Sources, a.Store.Get().Revision); err != nil {
		t.Fatal(err)
	}
	if err := a.recordAutonomyRoute(ctx, p, s, "usque"); err != nil {
		t.Fatal(err)
	}
	s = a.autonomy.doc.Services[s.ID]
	before := a.Store.Get()
	profile, err := a.freshNetworkProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := dataplane.Build(dataplane.Input{Revision: before.AppliedRevision, NetworkProfileID: profile,
		Routes:  []dataplane.Route{{ServiceID: service.ID, ServiceName: service.Name, Selected: "usque", Resolved: "usque", ProbeURL: service.ProbeURL, ProbeService: &service, CIDRs: service.CIDRs, Sources: s.Sources}},
		Engines: []dataplane.Engine{{ID: "usque", Installed: true, Configured: true, Activatable: true, Canary: true}},
		Host:    dataplane.HostState{IPCommand: true, TUN: true, SingBox: true}})
	if err != nil || !plan.Ready {
		t.Fatal("invalid committed fixture plan", err, plan.Blockers)
	}
	plan.State = "committed"
	if err := a.Dataplane.Record(plan); err != nil {
		t.Fatal(err)
	}
	if !autonomyCommittedUSQUERoute(plan, before, s, service, profile) {
		t.Fatal("fixture does not reach the post-commit owner path")
	}
	changed := s
	changed.Sources = []string{"192.168.1.51/32"}
	if autonomyCommittedUSQUERoute(plan, before, changed, service, profile) {
		t.Fatal("changed client scope reviewed old active path")
	}
	root := t.TempDir()
	a.EngineConfigs = engineconfig.New(filepath.Join(root, "draft"), filepath.Join(root, "backup"))
	a.TestLab = testlab.NewRunner()
	a.RouteProber = autonomyResourceRouteProber(func(ctx context.Context, service catalog.Service, route string) testlab.Result {
		t.Fatal("generic route probe was allowed to certify missing owned USQUE health", route)
		return testlab.Result{}
	})
	result := a.runAutonomyService(ctx, p, s, autonomyTestState(a), time.Now())
	if !reflect.DeepEqual(before, a.Store.Get()) || result.State != "unconfirmed" || len(result.Switches) != 0 || result.Failures != 0 || a.Operations.Snapshot().Fenced {
		t.Fatal("inconclusive owned monitoring did not keep committed service", result)
	}
}
