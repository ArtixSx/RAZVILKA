package dataplane

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestPolicyOwnershipSpecsMatchAdapterDefaults(t *testing.T) {
	specs := map[string]PolicyOwnershipSpec{}
	for _, spec := range PolicyOwnershipSpecs() {
		specs[spec.Adapter] = spec
		if spec.PriorityEnd-spec.PriorityBase+1 != maxPolicyPrefixes {
			t.Fatalf("%s priority range=%d..%d", spec.Adapter, spec.PriorityBase, spec.PriorityEnd)
		}
	}
	warp := NewWARPWireGuardAdapter(nil, t.TempDir())
	if spec := specs["warp-wg"]; spec.Interface != warp.Interface || spec.Table != warp.Table || spec.PriorityBase != warp.PriorityBase {
		t.Fatalf("WARP ownership spec drifted: spec=%+v adapter=%+v", spec, warp)
	}
	amnezia := NewAmneziaWGAdapter(nil, t.TempDir())
	if spec := specs["amneziawg"]; spec.Interface != amnezia.Interface || spec.Table != amnezia.Table || spec.PriorityBase != amnezia.PriorityBase {
		t.Fatalf("AmneziaWG ownership spec drifted: spec=%+v adapter=%+v", spec, amnezia)
	}
	for _, id := range []string{"usque", "sing-box", "xray"} {
		adapter, err := NewProxyTunnelAdapter(id, nil, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		spec := specs[id]
		if spec.Interface != adapter.Interface || spec.Table != adapter.Table || spec.PriorityBase != adapter.Priority {
			t.Fatalf("%s ownership spec drifted: spec=%+v adapter=%+v", id, spec, adapter)
		}
	}
}

func TestResolvePolicyPrefixesCombinesCIDRsAndDNS(t *testing.T) {
	plan := Plan{Routes: []Route{{Resolved: "warp-wg", Domains: []string{"example.com"}, CIDRs: []string{"203.0.113.0/24"}}}}
	got, err := resolvePolicyPrefixes(context.Background(), plan, "warp-wg", func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("198.51.100.4"), netip.MustParseAddr("192.168.1.1")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.4/32", "203.0.113.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prefixes=%v want=%v", got, want)
	}
}

func TestResolvePolicyRulesKeepsPerServiceDeviceScope(t *testing.T) {
	plan := Plan{Routes: []Route{
		{ServiceName: "Video", Resolved: "warp-wg", CIDRs: []string{"203.0.113.7/32"}, Sources: []string{"192.168.1.20/32"}},
		{ServiceName: "Chat", Resolved: "warp-wg", CIDRs: []string{"198.51.100.8/32"}, Sources: []string{"192.168.1.30/32"}},
	}}
	prefixes, rules, err := resolvePolicyRules(context.Background(), plan, "warp-wg", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 2 || len(rules) != 2 {
		t.Fatalf("prefixes=%v rules=%v", prefixes, rules)
	}
	want := map[string]string{"203.0.113.7/32": "192.168.1.20/32", "198.51.100.8/32": "192.168.1.30/32"}
	for _, rule := range rules {
		if want[rule.Destination] != rule.Source {
			t.Fatalf("scope was mixed: %+v", rule)
		}
	}
}

func TestApplyPolicyIncludesSourceSelector(t *testing.T) {
	runner := &nfqwsFakeRunner{}
	state := PolicyState{Interface: "rz-test", Table: 210, PriorityBase: 28000, Prefixes: []string{"203.0.113.7/32"}, Rules: []PolicyRule{{Source: "192.168.1.20/32", Destination: "203.0.113.7/32"}}}
	if err := applyPolicy(context.Background(), runner, "ip", state); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.calls, "\n")
	if !strings.Contains(joined, "rule add priority 28000 from 192.168.1.20/32 to 203.0.113.7/32 lookup 210") {
		t.Fatalf("source selector missing from calls:\n%s", joined)
	}
}
