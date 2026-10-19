package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/routekind"
)

func TestLegacyProxySharedDomainAddressRefusedBeforeCapture(t *testing.T) {
	// Synthetic domain fixtures illustrate the observed incident pattern:
	// unrelated services sharing one public IP. This is not historical DNS
	// evidence for the particular domain below.
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
		if err := a.Reconcile(context.Background(), candidate); !errors.Is(err, ErrProxyDomainAuthority) {
			t.Fatalf("reconciliation restored domain capture: %v", err)
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
	// The WireGuard family turns the same DNS answers into the same /32 capture
	// as the proxy TUN; a named profile is still the wireguard adapter.
	for _, engine := range []string{"sing-box", "xray", "usque", "warp-wg", "amneziawg", "wireguard", "wireguard:home"} {
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
				if blocker.Code == "DOMAIN_FLOW_AUTHORITY_REQUIRED" && blocker.Adapter == adapterID(engine) {
					found = true
				}
			}
			if found != domains || domains && plan.Ready || DomainFlowAuthority(engine) {
				t.Fatalf("engine=%s domains=%v ready=%v blocker=%v", engine, domains, plan.Ready, found)
			}
		}
	}
	// Per-connection hostname matching and no capture at all keep domains.
	for _, engine := range []string{"nfqws2", "direct"} {
		plan, err := Build(Input{Routes: []Route{{ServiceID: "youtube", Resolved: engine, Domains: []string{"youtube.com"}}}})
		if err != nil {
			t.Fatal(err)
		}
		for _, blocker := range plan.Blockers {
			if blocker.Code == "DOMAIN_FLOW_AUTHORITY_REQUIRED" {
				t.Fatalf("%s domain route was fenced", engine)
			}
		}
		if !DomainFlowAuthority(engine) {
			t.Fatalf("%s lost domain authority", engine)
		}
	}
}

// One answer for Build, the WireGuard/proxy adapters and the autopilot: every
// adapter except NFQWS2 and direct is an IP-policy executor, and an unknown
// route has no authority at all.
func TestDomainFlowAuthorityCoversEveryIPPolicyAdapter(t *testing.T) {
	for _, id := range append(routekind.PreferredIDs(), "direct") {
		ipPolicy := slices.Contains(domainCaptureAdapters, id)
		if adapterID(id) != id || DomainFlowAuthority(id) == ipPolicy {
			t.Fatalf("%s: ip-policy=%v authority=%v", id, ipPolicy, DomainFlowAuthority(id))
		}
	}
	if len(domainCaptureAdapters) != routekind.PreferredCount-1 {
		t.Fatal("an IP-policy adapter is missing from the domain blocker", domainCaptureAdapters)
	}
	for _, route := range []string{"", "auto", "mihomo", "direct-x", "nfqws2-x"} {
		if DomainFlowAuthority(route) {
			t.Fatalf("unknown route %q gained domain authority", route)
		}
	}
}

func TestLegacyProxyDomainBlockerCannotBeWaivedByTypedMaterialPointer(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		route := Route{Resolved: "xray:node-fixture", Domains: []string{"service.example"}}
		if mixed {
			route.CIDRs = []string{"8.6.112.1/32"}
		}
		plan, err := Build(Input{Routes: []Route{route}, managedXraySelectedTCP: new(XrayOperationMaterial)})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, blocker := range plan.Blockers {
			if blocker.Code == "DOMAIN_FLOW_AUTHORITY_REQUIRED" {
				found = true
			}
		}
		if !found || plan.Ready {
			t.Fatal("domain/mixed intent bypassed domain blocker")
		}
	}
}
