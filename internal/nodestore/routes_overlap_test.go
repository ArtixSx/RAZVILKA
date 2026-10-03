package nodestore

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func routeOverlapFixture(t *testing.T, engine string) (*Store, []string) {
	t.Helper()
	store, _ := setup(t)
	snapshot, err := store.Import(context.Background(), manual, good+"\n"+strings.Replace(good, "private-host", "other-host", 1), testTime, time.Hour, false)
	if err != nil || len(snapshot.Nodes) != 2 {
		t.Fatalf("two-node fixture: %v", err)
	}
	ids := []string{snapshot.Nodes[0].ID, snapshot.Nodes[1].ID}
	for index, id := range ids {
		pass := enginePass(id, engine, "overlap-pass-"+string(rune('a'+index)), testTime)
		if _, err := store.RecordCheck(context.Background(), id, pass, testTime); err != nil {
			t.Fatal(err)
		}
	}
	return store, ids
}

func overlapMaterialize(store *Store, engine string, bindings []RouteBinding, now time.Time) (RouteMaterial, error) {
	if engine == "xray" {
		return store.MaterializeXray(context.Background(), bindings, now)
	}
	return store.MaterializeSingBox(context.Background(), bindings, now)
}

func TestMaterializersRejectOverlappingDestinationOwnersInEitherOrder(t *testing.T) {
	for _, engine := range []string{"sing-box", "xray"} {
		t.Run(engine, func(t *testing.T) {
			store, ids := routeOverlapFixture(t, engine)
			for _, scenario := range []struct {
				name    string
				domains bool
				first   string
				second  string
			}{
				{name: "IPv4-nested", first: "149.154.160.0/20", second: "149.154.164.0/24"},
				{name: "IPv4-host", first: "149.154.160.0/20", second: "149.154.164.1"},
				{name: "IPv4-masked", first: "149.154.164.7/24", second: "149.154.164.0/24"},
				{name: "IPv6-nested", first: "2606:4700::/32", second: "2606:4700:4700::/48"},
				{name: "IPv6-host", first: "2606:4700::/32", second: "2606:4700:4700::1111/128"},
				{name: "domain-nested", domains: true, first: "example.com", second: "api.example.com"},
				{name: "domain-normalized", domains: true, first: " *.EXAMPLE.com. ", second: " Api.Example.Com. "},
				{name: "domain-equal", domains: true, first: "EXAMPLE.com.", second: "*.example.com"},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					bindings := []RouteBinding{
						{ServiceID: "telegram", NodeID: ids[0], NetworkProfile: "wan-0123456789ab"},
						{ServiceID: "telegram", NodeID: ids[1], NetworkProfile: "wan-0123456789ab"},
					}
					if scenario.domains {
						bindings[0].Domains, bindings[1].Domains = []string{scenario.first}, []string{scenario.second}
					} else {
						bindings[0].Destinations, bindings[1].Destinations = []string{scenario.first}, []string{scenario.second}
					}
					for order := 0; order < 2; order++ {
						if err := ValidateRouteDestinationOwners(bindings); !errors.Is(err, ErrRouteProof) {
							t.Fatalf("order %d: shared validation accepted conflicting owners: %v", order, err)
						}
						material, err := overlapMaterialize(store, engine, bindings, testTime.Add(time.Minute))
						if !errors.Is(err, ErrRouteProof) || len(material.Config) != 0 || len(material.EndpointHosts) != 0 {
							t.Fatalf("order %d: conflicting scope materialized: %v", order, err)
						}
						bindings[0], bindings[1] = bindings[1], bindings[0]
					}
				})
			}
		})
	}
}

func TestMaterializersAllowDisjointAndSameOwnerNestedDestinations(t *testing.T) {
	for _, engine := range []string{"sing-box", "xray"} {
		t.Run(engine, func(t *testing.T) {
			store, ids := routeOverlapFixture(t, engine)
			for _, scenario := range []struct {
				name       string
				sameOwner  bool
				firstNames []string
				lastNames  []string
				firstCIDRs []string
				lastCIDRs  []string
			}{
				{name: "same-owner-nested", sameOwner: true, firstNames: []string{"*.EXAMPLE.com."}, lastNames: []string{"api.example.com"}, firstCIDRs: []string{"149.154.160.0/20", "2606:4700::/32"}, lastCIDRs: []string{"149.154.164.0/24", "2606:4700:4700::/48"}},
				{name: "different-owner-disjoint", firstNames: []string{"api.example.com"}, lastNames: []string{"cdn.example.com", "badapi.example.com"}, firstCIDRs: []string{"149.154.160.0/24", "2606:4700:4700::/48"}, lastCIDRs: []string{"149.154.161.0/24", "2606:4700:4701::/48"}},
				{name: "same-owner-disjoint", sameOwner: true, firstNames: []string{"example.com"}, lastNames: []string{"example.net"}, firstCIDRs: []string{"149.154.160.0/24"}, lastCIDRs: []string{"149.154.161.0/24"}},
				{name: "domain-label-boundary", firstNames: []string{"example.com"}, lastNames: []string{"badexample.com"}},
				{name: "different-address-families", firstCIDRs: []string{"149.154.160.0/20"}, lastCIDRs: []string{"2606:4700::/32"}},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					lastOwner := ids[1]
					if scenario.sameOwner {
						lastOwner = ids[0]
					}
					bindings := []RouteBinding{
						{ServiceID: "telegram", NodeID: ids[0], NetworkProfile: "wan-0123456789ab", Domains: scenario.firstNames, Destinations: scenario.firstCIDRs},
						{ServiceID: "telegram", NodeID: lastOwner, NetworkProfile: "wan-0123456789ab", Domains: scenario.lastNames, Destinations: scenario.lastCIDRs},
					}
					for order := 0; order < 2; order++ {
						if err := ValidateRouteDestinationOwners(bindings); err != nil {
							t.Fatalf("order %d: safe destination owners rejected: %v", order, err)
						}
						material, err := overlapMaterialize(store, engine, bindings, testTime.Add(time.Minute))
						if err != nil || material.EngineID != engine || !json.Valid(material.Config) {
							t.Fatalf("order %d: safe scope failed materialization: %v", order, err)
						}
						bindings[0], bindings[1] = bindings[1], bindings[0]
					}
				})
			}
		})
	}
}

func TestDestinationOwnerValidationDoesNotGrantRouteProof(t *testing.T) {
	for _, engine := range []string{"sing-box", "xray"} {
		t.Run(engine, func(t *testing.T) {
			store, ids := routeOverlapFixture(t, engine)
			bindings := []RouteBinding{{NodeID: ids[0], Domains: []string{"example.com"}}}
			if err := ValidateRouteDestinationOwners(bindings); err != nil {
				t.Fatal("pure destination check required unrelated proof fields", err)
			}
			if _, err := overlapMaterialize(store, engine, bindings, testTime.Add(time.Minute)); !errors.Is(err, ErrRouteProof) {
				t.Fatal("destination validation granted unscoped service proof", err)
			}
			bindings[0].ServiceID, bindings[0].NetworkProfile = "telegram", "wan-0123456789ab"
			otherEngine := "xray"
			if engine == "xray" {
				otherEngine = "sing-box"
			}
			if _, err := overlapMaterialize(store, otherEngine, bindings, testTime.Add(time.Minute)); !errors.Is(err, ErrRouteProof) {
				t.Fatal("destination validation borrowed another engine's proof", err)
			}
			if _, err := overlapMaterialize(store, engine, bindings, testTime.Add(30*time.Minute)); !errors.Is(err, ErrRouteProof) {
				t.Fatal("destination validation retained expired exact proof", err)
			}
		})
	}
}

func TestDestinationOwnerValidationBoundsRawInputs(t *testing.T) {
	store, ids := routeOverlapFixture(t, "xray")
	binding := RouteBinding{ServiceID: "telegram", NodeID: ids[0], NetworkProfile: "wan-0123456789ab", Domains: []string{"example.com"}}
	bindings := make([]RouteBinding, maxRouteBindings)
	for i := range bindings {
		bindings[i] = binding
	}
	if _, err := store.MaterializeXray(context.Background(), bindings, testTime.Add(time.Minute)); err != nil {
		t.Fatal("bounded service count rejected", err)
	}
	if err := ValidateRouteDestinationOwners(append(bindings, binding)); !errors.Is(err, ErrRouteProof) {
		t.Fatal("raw binding count was unbounded", err)
	}
	bindings = []RouteBinding{binding, binding}
	bindings[0].Domains = make([]string, maxRouteDestinations/2)
	bindings[1].Destinations = make([]string, maxRouteDestinations/2)
	bindings[1].Domains = nil
	for i := range bindings[0].Domains {
		bindings[0].Domains[i] = "example.com"
		bindings[1].Destinations[i] = "149.154.160.0/20"
	}
	if _, err := store.MaterializeXray(context.Background(), bindings, testTime.Add(time.Minute)); err != nil {
		t.Fatal("bounded total destinations rejected", err)
	}
	bindings[1].Destinations = append(bindings[1].Destinations, "149.154.160.0/20")
	if _, err := store.MaterializeXray(context.Background(), bindings, testTime.Add(time.Minute)); !errors.Is(err, ErrRouteProof) {
		t.Fatal("duplicates bypassed combined raw destination bound", err)
	}
	bindings = []RouteBinding{binding}
	bindings[0].Domains = []string{strings.Repeat("a", maxRouteDestinationBytes+1)}
	if err := ValidateRouteDestinationOwners(bindings); !errors.Is(err, ErrRouteProof) {
		t.Fatal("raw destination bytes were unbounded", err)
	}
}

func TestDestinationOwnerValidationRejectsMalformedAndMappedScopes(t *testing.T) {
	store, ids := routeOverlapFixture(t, "xray")
	for _, scenario := range []struct {
		name         string
		domains      []string
		destinations []string
	}{
		{name: "empty"},
		{name: "empty-domain", domains: []string{"example.com", ""}},
		{name: "empty-label", domains: []string{"api..example.com"}},
		{name: "domain-path", domains: []string{"example.com/path"}},
		{name: "domain-newline", domains: []string{"api\n.example.com"}},
		{name: "invalid-domain-wildcard", domains: []string{"api.*.example.com"}},
		{name: "invalid-prefix", destinations: []string{"not-a-prefix"}},
		{name: "mapped-address", destinations: []string{"::ffff:149.154.164.1"}},
		{name: "mapped-prefix", destinations: []string{"::ffff:149.154.164.0/120"}},
		{name: "private-prefix", destinations: []string{"10.0.0.0/8"}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			bindings := []RouteBinding{{ServiceID: "telegram", NodeID: ids[0], NetworkProfile: "wan-0123456789ab", Domains: scenario.domains, Destinations: scenario.destinations}}
			if err := ValidateRouteDestinationOwners(bindings); !errors.Is(err, ErrRouteProof) {
				t.Fatal("invalid destination scope accepted", err)
			}
			if _, err := store.MaterializeXray(context.Background(), bindings, testTime.Add(time.Minute)); !errors.Is(err, ErrRouteProof) {
				t.Fatal("invalid destination scope materialized", err)
			}
		})
	}
}
