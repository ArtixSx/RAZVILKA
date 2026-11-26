package app

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"reflect"
	"testing"
)

func newSelectedTCPInlineScopeFixture(t *testing.T) (*listXraySourceFixture, catalog.Service) {
	t.Helper()
	f, service, _ := newListXrayInlineFixture(t)
	prior := f.a.Store.Get().Services["listed"]
	prior.Enabled = false
	if err := f.a.Store.UpdateService("listed", prior); err != nil {
		t.Fatal(err)
	}
	if err := f.scope.Close(); err != nil {
		t.Fatal(err)
	}
	listScopeOperation(t, f.a, func(ctx context.Context) {
		var err error
		f.scope, err = newListScopeBinding(ctx, f.a, f.physical.acquire)
		if err != nil {
			t.Fatal(err)
		}
	})
	return f, service
}

// Actual saved inline service, node source, Store/control and compiler; physics
// and the initial recorded check are explicitly the existing unit models.
func TestListXraySelectedScopePreservesBothDestinationsAndOneOriginalPC(t *testing.T) {
	f, service := newSelectedTCPInlineScopeFixture(t)
	listScopeOperation(t, f.a, func(ctx context.Context) {
		r, err := f.a.ReviewXrayListRuntimeSource(ctx, f.scope, service.ID, f.adapter)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		p, err := r.prepare(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		defer p.close()
		lan := p.compilation.LAN()
		if lan.Mode != dataplane.LANPolicyXraySelectedTCPMode || len(lan.Ingress) != 1 || !reflect.DeepEqual(lan.Ingress[0].Sources, []string{"192.168.1.40/32"}) || !reflect.DeepEqual(lan.Ingress[0].IncludedMACs, []string{"02:00:00:00:00:01"}) {
			t.Fatal("consumer expanded original PC", lan)
		}
		var destinations []string
		for _, rule := range p.compilation.Rules() {
			if rule.Source.String() != "192.168.1.40/32" || rule.Protocol != "tcp" || rule.FirstPort != 443 || rule.LastPort != 443 {
				t.Fatal("unrestricted traffic escaped dedicated compilation", rule)
			}
			destinations = append(destinations, rule.Destination.String())
		}
		if !reflect.DeepEqual(destinations, service.CIDRs) {
			t.Fatal("one original service destination dropped", destinations, service.CIDRs)
		}
		if err := f.scope.ScopeCheck(ctx, lan); err != nil {
			t.Fatal("not bound before use", err)
		}
		planInput := (&DefaultRouteExecutor{app: f.a}).input(p.compilation, r.expected)
		if len(planInput.Routes) != 1 || !reflect.DeepEqual(planInput.Routes[0].CIDRs, service.CIDRs) || !reflect.DeepEqual(planInput.Routes[0].Sources, lan.Ingress[0].Sources) {
			t.Fatal("ordinary compiler lost scope/destinations")
		}
	})
}

func TestListXraySelectedScopeRefusesUnknownOrAmbiguousMember(t *testing.T) {
	for _, change := range []string{"missing-member", "two-ipv4", "two-macs", "excluded-client"} {
		t.Run(change, func(t *testing.T) {
			f, service := newSelectedTCPInlineScopeFixture(t)
			listScopeOperation(t, f.a, func(ctx context.Context) {
				r, err := f.a.ReviewXrayListRuntimeSource(ctx, f.scope, service.ID, f.adapter)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				p, err := r.prepare(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer p.close()
				c := p.compilation
				c.lan = dataplane.CloneLANPolicyRuntime(c.lan)
				switch change {
				case "missing-member":
					r.scope.facts.Devices = nil
				case "two-ipv4":
					r.scope.facts.Devices[0].Addresses = []string{"192.168.1.40", "192.168.1.41"}
				case "two-macs":
					c.lan.Ingress[0].IncludedMACs = append(c.lan.Ingress[0].IncludedMACs, "02:00:00:00:00:02")
				case "excluded-client":
					c.lan.Ingress[0].ExcludedSources = []string{"192.168.1.40/32"}
				}
				if err := r.narrowSelectedTCP(c); err == nil {
					t.Fatal("ambiguous scope accepted")
				}
			})
		})
	}
}
