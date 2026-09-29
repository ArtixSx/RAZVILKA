package config

import "testing"

func allInternetPolicy() *NetworkPolicy {
	p := networkPolicyFixture()
	p.Schema = 2
	p.Traffic = TrafficSelection{Mode: "all_except", AllExceptAllowed: true, DefaultRoute: DefaultRouteAuto, Unavailable: "block"}
	return p
}

// G03-T03: auto stays an intent; applied state names a concrete executor.
func TestAllInternetDefaultRouteIntentAndAppliedIdentity(t *testing.T) {
	if err := ValidateNetworkPolicy(allInternetPolicy()); err != nil {
		t.Fatalf("all-internet auto intent rejected: %v", err)
	}
	if err := ValidateAppliedNetworkPolicy(allInternetPolicy()); err == nil {
		t.Fatal("auto intent stored as applied state")
	}
	for _, route := range []string{"xray", "amneziawg", "wireguard", "usque", "warp-wg", "sing-box:node-abc"} {
		p := allInternetPolicy()
		p.Traffic.DefaultRoute = route
		if err := ValidateAppliedNetworkPolicy(p); err != nil {
			t.Fatalf("%s: %v", route, err)
		}
	}
	for _, route := range []string{"", "nfqws2", "direct", "sing-box:group-abc", "wireguard:other"} {
		p := allInternetPolicy()
		p.Traffic.DefaultRoute = route
		if ValidateNetworkPolicy(p) == nil {
			t.Fatalf("%q accepted as a full default path", route)
		}
	}
	p := allInternetPolicy()
	p.Traffic.AllExceptAllowed = false
	if ValidateNetworkPolicy(p) == nil {
		t.Fatal("all-internet mode without explicit consent")
	}
}

// G03-T05: schema 1 keeps its original values, so a schema 1 policy never
// carries semantics that an older strict decoder would misread.
func TestLegacySchemaRejectsAllInternetValues(t *testing.T) {
	for name, change := range map[string]func(*NetworkPolicy){
		"auto":      func(p *NetworkPolicy) { p.Traffic.DefaultRoute = DefaultRouteAuto },
		"block":     func(p *NetworkPolicy) { p.Traffic.Unavailable = "block" },
		"amneziawg": func(p *NetworkPolicy) { p.Traffic.DefaultRoute = "amneziawg" },
	} {
		p := allInternetPolicy()
		p.Traffic.DefaultRoute = "usque"
		p.Traffic.Unavailable = "retain"
		change(p)
		p.Schema = 1
		if ValidateNetworkPolicy(p) == nil {
			t.Fatalf("schema 1 accepted %s", name)
		}
	}
	if err := ValidateAppliedNetworkPolicy(networkPolicyFixture()); err != nil {
		t.Fatalf("legacy selected-services policy rejected: %v", err)
	}
}

// G03-T04: opposite mandatory rules are a conflict, not a lexicographic winner.
func TestAllInternetOppositeMandatoryRulesRejected(t *testing.T) {
	p := allInternetPolicy()
	p.Rules = []NetworkRule{
		{ID: "a-direct", Revision: 1, Kind: "suffix", Value: "example.com", Action: "direct", Mandatory: true},
		{ID: "b-bypass", Revision: 1, Kind: "exact", Value: "www.example.com", Action: "bypass", Mandatory: true},
	}
	if ValidateNetworkPolicy(p) == nil {
		t.Fatal("opposite mandatory rules accepted")
	}
	p.Rules[1].Mandatory = false
	if err := ValidateNetworkPolicy(p); err != nil {
		t.Fatalf("ordinary bypass under a mandatory direct rejected: %v", err)
	}
}
