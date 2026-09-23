package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func networkPolicyFixture() *NetworkPolicy {
	return &NetworkPolicy{Schema: 1, Revision: 1, Clients: ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, NewDevices: "inherit"}, Traffic: TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
}

func TestNetworkPolicyValidationSeparatesClientsAndTraffic(t *testing.T) {
	tests := []struct {
		name   string
		change func(*NetworkPolicy)
		valid  bool
	}{
		{"home selected services", func(p *NetworkPolicy) {}, true},
		{"selected devices", func(p *NetworkPolicy) {
			p.Clients.Mode = "selected_devices"
			p.Clients.DeviceIDs = []string{"device-laptop"}
			p.Clients.NewDevices = "base"
		}, true},
		{"no implicit devices", func(p *NetworkPolicy) { p.Clients.Mode = "selected_devices" }, false},
		{"no positive catchall ambiguity", func(p *NetworkPolicy) { p.Clients.DeviceIDs = []string{"device-laptop"} }, false},
		{"no implicit internet", func(p *NetworkPolicy) { p.Traffic.Mode = "all_except"; p.Traffic.DefaultRoute = "usque" }, false},
		{"approved full route", func(p *NetworkPolicy) {
			p.Traffic.Mode = "all_except"
			p.Traffic.AllExceptAllowed = true
			p.Traffic.DefaultRoute = "usque"
		}, true},
		{"NFQWS is not full tunnel", func(p *NetworkPolicy) {
			p.Traffic.Mode = "all_except"
			p.Traffic.AllExceptAllowed = true
			p.Traffic.DefaultRoute = "nfqws2"
		}, false},
		{"segment missing", func(p *NetworkPolicy) { p.Clients.SegmentIDs = nil }, false},
		{"all networks", func(p *NetworkPolicy) { p.Clients.ExcludedCIDRs = []string{"0.0.0.0/0"} }, false},
		{"noncanonical CIDR", func(p *NetworkPolicy) { p.Clients.ExcludedCIDRs = []string{"192.168.1.1/24"} }, false},
		{"IPv6 exclusion", func(p *NetworkPolicy) { p.Clients.ExcludedCIDRs = []string{"fd00:1::/64"} }, true},
		{"future schema", func(p *NetworkPolicy) { p.Schema++ }, false},
		{"no revision", func(p *NetworkPolicy) { p.Revision = 0 }, false},
		{"unapproved TLD", func(p *NetworkPolicy) { p.Russian.BroadTLDs = []string{"ru"} }, false},
		{"unapproved updates", func(p *NetworkPolicy) { p.Russian.AutoUpdateAllowed = true }, false},
		{"curated snapshot", func(p *NetworkPolicy) {
			p.Russian = RussianExclusions{Enabled: true, CatalogID: "ru-curated", Revision: 2, Digest: strings.Repeat("a", 64), ServiceIDs: []string{"bank"}}
		}, true},
		{"no unfrozen catalog", func(p *NetworkPolicy) {
			p.Russian = RussianExclusions{Enabled: true, CatalogID: "ru-curated", Revision: 2, ServiceIDs: []string{"bank"}}
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := networkPolicyFixture()
			tt.change(p)
			if err := ValidateNetworkPolicy(p); (err == nil) != tt.valid {
				t.Fatalf("valid=%v error=%v", tt.valid, err)
			}
		})
	}
}

func TestPolicyDomainIdentityAndRuleConflicts(t *testing.T) {
	for input, want := range map[string]string{"EXAMPLE.RU.": "example.ru", "пример.рф": "xn--e1afmkfd.xn--p1ai", "bank.example.ru": "bank.example.ru"} {
		got, err := PolicyDomain(input)
		if err != nil || got != want {
			t.Fatalf("%q = %q, %v", input, got, err)
		}
	}
	for _, input := range []string{"ru", "co.uk", "github.io", "appspot.com", "https://example.ru/path", "example.ru/a", "*.example.ru", "1.1.1.1", "example..ru", "evil_1.ru"} {
		if _, err := PolicyDomain(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
	direct := NetworkRule{ID: "direct", Revision: 1, Kind: "suffix", Value: "example.ru", Action: "direct", Mandatory: true}
	for _, tt := range []struct {
		value   string
		overlap bool
	}{{"example.ru", true}, {"bank.example.ru", true}, {"example.ru.attacker.test", false}, {"notexample.ru", false}} {
		bypass := NetworkRule{ID: "bypass", Revision: 1, Kind: "exact", Value: tt.value, Action: "bypass", Mandatory: true}
		p := networkPolicyFixture()
		p.Rules = []NetworkRule{direct, bypass}
		if err := ValidateNetworkPolicy(p); (err != nil) != tt.overlap {
			t.Errorf("%s overlap=%v err=%v", tt.value, tt.overlap, err)
		}
		p.Rules[0].DeviceIDs = []string{"laptop"}
		p.Rules[1].DeviceIDs = []string{"phone"}
		if err := ValidateNetworkPolicy(p); err != nil {
			t.Fatal("different client rules conflict", err)
		}
	}
	a := NetworkRule{Kind: "cidr", Value: "203.0.113.0/24"}
	b := NetworkRule{Kind: "ip", Value: "203.0.113.1"}
	if !NetworkRulesOverlap(a, b) {
		t.Fatal("IP inside prefix not detected")
	}
}

func TestNetworkPolicyStorageCloneAndNoLegacyScopeExpansion(t *testing.T) {
	old, _, err := InspectBytes([]byte(`{"schema_version":2,"services":{"telegram":{"enabled":true,"route":"auto","sources":["192.168.1.40/32"]}},"safe_mode":true}`))
	if err != nil || old.NetworkPolicy != nil || old.AppliedNetworkPolicy != nil || !old.SafeMode || len(old.Services["telegram"].Sources) != 1 {
		t.Fatalf("legacy changed: %+v %v", old, err)
	}
	cfg := Default()
	cfg.NetworkPolicy = networkPolicyFixture()
	cfg.AppliedNetworkPolicy = CloneNetworkPolicy(cfg.NetworkPolicy)
	cfg.NetworkPolicy.Rules = []NetworkRule{{ID: "rule", Revision: 1, Kind: "exact", Value: "example.ru", Action: "direct", Mandatory: true, DeviceIDs: []string{"laptop"}}}
	cfg.NetworkPolicy.Clients.ExcludedDeviceIDs = []string{"phone"}
	cfg.NetworkPolicy.Russian.ServiceIDs = []string{"bank"}
	data, _ := json.Marshal(cfg)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := store.Get()
	got.NetworkPolicy.Rules[0].DeviceIDs[0] = "changed"
	got.NetworkPolicy.Clients.ExcludedDeviceIDs[0] = "changed"
	got.NetworkPolicy.Russian.ServiceIDs[0] = "changed"
	got.AppliedNetworkPolicy.Clients.SegmentIDs[0] = "changed"
	if !reflect.DeepEqual(store.Get(), cfg) {
		t.Fatal("Get leaked mutable slices")
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reloaded.Get().NetworkPolicy, cfg.NetworkPolicy) || !reflect.DeepEqual(reloaded.Get().AppliedNetworkPolicy, cfg.AppliedNetworkPolicy) {
		t.Fatal("unrelated update lost policy")
	}
	cfg.NetworkPolicy.Clients.SegmentIDs = nil
	data, _ = json.Marshal(cfg)
	if _, _, err := InspectBytes(data); err == nil {
		t.Fatal("restore accepted incomplete scope")
	}
}
