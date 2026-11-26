package app

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

func TestAutonomyMixedNFQWS2RefusalRequiresConfirmedCurrentProfile(t *testing.T) {
	for _, test := range []struct {
		name             string
		domains, cidrs   []string
		current, refused bool
	}{
		{"closed mixed", []string{"telegram.example"}, []string{"149.154.160.0/20"}, true, true},
		{"external or unknown mixed", []string{"telegram.example"}, []string{"149.154.160.0/20"}, false, false},
		{"domains only", []string{"telegram.example"}, nil, true, false},
		{"CIDRs only", nil, []string{"149.154.160.0/20"}, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			reads := 0
			service := catalog.Service{ID: "telegram-networks", Domains: test.domains, CIDRs: test.cidrs}
			refusal := autonomyNFQWS2MixedRefusal(context.Background(), service, func(context.Context) bool { reads++; return test.current })
			if (refusal != nil) != test.refused || len(test.domains)*len(test.cidrs) == 0 && reads != 0 {
				t.Fatal("unproved or unmixed profile classified", refusal, reads)
			}
			if refusal != nil && (refusal.Code != capabilityNFQWS2MixedService || refusal.ServiceID != service.ID || strings.Contains(refusal.Resolution, "стратег")) {
				t.Fatal("mixed capability lost its typed service limit", refusal)
			}
		})
	}
}

func TestAutonomyMixedNFQWS2RefusesBeforeProbeAndBudget(t *testing.T) {
	service := catalog.Service{ID: "telegram-networks", Name: "Telegram", Domains: []string{"telegram.example"}, CIDRs: []string{"149.154.160.0/20"}, ProbeURL: "https://telegram.example/"}
	a, adapter, rec := domainAutopilotFixture(t, service, true)
	service, _ = a.autonomyService(service.ID)
	a.autonomy.mu.Lock()
	p, spec, state := autonomy.Clone(a.autonomy.doc.Policy), a.autonomy.doc.Services[service.ID], a.autonomy.doc.Runtime[service.ID].Clone()
	a.autonomy.mu.Unlock()
	state.Search = &autonomy.Traversal{Version: "bound-prefix", Ordered: []string{"consumed", "pending"}, Cursor: 1, StandardRoutesTried: true}
	state.Switches = []time.Time{time.Now().Add(-time.Minute)}
	state.FirstFailure = time.Now().Add(-time.Minute)
	state.Failures = 1
	before := a.Store.Get()
	committed, _, _ := a.Dataplane.Committed()
	reads := 0
	next, done := a.tryAutonomyPreferredRoutesWithNFQWS2Review(context.Background(), p, spec, state, before, service, "", func(context.Context) bool { reads++; return true })
	if !done || reads != 1 || next.State != "capability-refused" || !strings.Contains(next.Message, "одновременно домены и IP-сети") || len(rec.routes()) != 0 || len(adapter.calls) != 0 || rec.nodeChecks != 0 {
		t.Fatal("unsupported mixed profile incurred network or Apply work", next, reads, rec.routes(), adapter.calls)
	}
	state.State, state.Message = next.State, next.Message
	if !reflect.DeepEqual(state, next) {
		t.Fatal("refusal consumed switch/search/failure budget", state, next)
	}
	current, _, _ := a.Dataplane.Committed()
	if !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(committed, current) {
		t.Fatal("refusal changed settings or committed route")
	}
	// Unknown/external NFQ is not blocked by this closed-profile capability.
	profile, err := a.freshNetworkProfile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, done = a.tryAutonomyPreferredRoutesWithNFQWS2Review(context.Background(), p, spec, state, before, service, profile, func(context.Context) bool { return false })
	if done {
		t.Fatal("external NFQ profile was statically denied", done, rec.routes())
	}
}

func TestAutonomyMixedNFQWS2KeepsHealthyCurrentRoute(t *testing.T) {
	service := catalog.Service{ID: "telegram-networks", Name: "Telegram", Domains: []string{"telegram.example"}, CIDRs: []string{"149.154.160.0/20"}, ProbeURL: "https://telegram.example/"}
	a, adapter, _ := domainAutopilotFixture(t, service, true)
	if err := a.Store.UpdateService(service.ID, config.ServiceState{Enabled: true, Route: "nfqws2", Sources: []string{"192.168.1.50/32"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	if err := a.inheritAutonomyService(context.Background(), service.ID); err != nil {
		t.Fatal(err)
	}
	a.TestLab = testlab.NewRunner()
	a.RouteProber = confirmedRouteProber{}
	a.autonomy.mu.Lock()
	reviewed := a.autonomy.doc.Services[service.ID]
	reviewed.DraftFingerprint = autonomyDraftFingerprint(a.Store.Get().Services[service.ID])
	a.autonomy.doc.Services[service.ID] = reviewed
	if err := a.persistAutonomyLocked(context.Background()); err != nil {
		a.autonomy.mu.Unlock()
		t.Fatal(err)
	}
	a.autonomy.mu.Unlock()
	before := a.Store.Get()
	domainAutopilotDue(a, service.ID)
	a.autonomyRound(context.Background(), time.Now())
	a.autonomy.mu.Lock()
	next := a.autonomy.doc.Runtime[service.ID].Clone()
	a.autonomy.mu.Unlock()
	if next.State != "healthy" || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("mixed capability replaced/refused a healthy current route", next, adapter.calls)
	}
}
