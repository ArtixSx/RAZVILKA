package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyProxySharedDomainAddressRefusedBeforeCapture(t *testing.T) {
	// These two unrelated domains actually shared this public address during
	// the reported incident. DNS-derived membership cannot identify a flow.
	shared := netip.MustParseAddr("8.6.112.1")
	plan := Plan{Routes: []Route{{ServiceID: "telegram", Resolved: "sing-box:node-public", Domains: []string{"telegram.org"}, Sources: []string{"192.0.2.40/32"}}}}
	resolver := func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{shared}, nil }
	prefixes, err := resolvePolicyPrefixes(context.Background(), plan, "sing-box", resolver)
	if err != nil || len(prefixes) != 1 || prefixes[0] != "8.6.112.1/32" {
		t.Fatalf("shared-IP reproduction failed: %v %v", prefixes, err)
	}
	sidecar, err := buildSOCKSTunnelConfigForSchema("rz-test", "198.18.0.1/30", 12345, singBoxSidecarSchema{})
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err = json.Unmarshal(sidecar, &config); err != nil {
		t.Fatal(err)
	}
	if config["route"].(map[string]any)["final"] != "rz-socks-out" {
		t.Fatal("reproduction no longer uses IP-only final SOCKS")
	}
	for _, mixed := range []bool{false, true} {
		candidate := plan
		candidate.Routes = append([]Route(nil), plan.Routes...)
		if mixed {
			candidate.Routes[0].CIDRs = []string{"149.154.160.0/20"}
		}
		root := filepath.Join(t.TempDir(), "never-created")
		a := &ProxyTunnelAdapter{EngineID: "sing-box", Resolver: func(context.Context, string) ([]netip.Addr, error) {
			t.Fatal("refusal must precede DNS and runtime work")
			return nil, nil
		}}
		if err := a.Stage(context.Background(), candidate, root); !errors.Is(err, ErrProxyDomainAuthority) {
			t.Fatalf("mixed=%v: %v", mixed, err)
		}
		if err := a.Activate(context.Background(), candidate, root); !errors.Is(err, ErrProxyDomainAuthority) {
			t.Fatalf("activation accepted domain capture: %v", err)
		}
		if _, err := os.Stat(root); !os.IsNotExist(err) {
			t.Fatal("refused stage wrote artifacts")
		}
		if changed, err := a.RefreshPolicy(context.Background(), candidate); changed || !errors.Is(err, ErrProxyDomainAuthority) {
			t.Fatalf("refresh extended unsafe capture: %v %v", changed, err)
		}
	}
	if strings.Contains(ErrProxyDomainAuthority.Error(), "telegram") || strings.Contains(ErrProxyDomainAuthority.Error(), shared.String()) {
		t.Fatal("reason contains private flow material")
	}
}

func TestLegacyProxyExplicitCIDRAuthorityIsSeparate(t *testing.T) {
	a := &ProxyTunnelAdapter{EngineID: "sing-box"}
	plan := Plan{Routes: []Route{{Resolved: "sing-box:node-public", CIDRs: []string{"149.154.160.0/20"}}, {Resolved: "xray", Domains: []string{"other.example"}}}}
	if err := a.requireLegacyIPPolicyAuthority(plan); err != nil {
		t.Fatal(err)
	}
	// The CIDR-only path still reaches its ordinary snapshot/admission checks.
	if err := a.Stage(context.Background(), plan, t.TempDir()); err == nil || errors.Is(err, ErrProxyDomainAuthority) {
		t.Fatalf("ordinary checks bypassed: %v", err)
	}
}

func TestLegacyProxyDomainPlanHasPreflightBlocker(t *testing.T) {
	for _, engine := range []string{"sing-box", "xray", "usque"} {
		for _, domains := range []bool{false, true} {
			route := Route{ServiceID: "telegram", Resolved: engine, CIDRs: []string{"149.154.160.0/20"}}
			if domains {
				route.Domains = []string{"telegram.org"}
			}
			plan, err := Build(Input{Routes: []Route{route}})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, blocker := range plan.Blockers {
				if blocker.Code == "DOMAIN_FLOW_AUTHORITY_REQUIRED" && blocker.Adapter == engine {
					found = true
				}
			}
			if found != domains || domains && plan.Ready {
				t.Fatalf("engine=%s domains=%v ready=%v blocker=%v", engine, domains, plan.Ready, found)
			}
		}
	}
}
