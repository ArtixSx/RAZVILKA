package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodequality"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

func TestScopedNodeEndpointSelectionPinsFirstConfirmedAddress(t *testing.T) {
	for _, pair := range [][2]string{{"8.8.4.4", "1.1.1.1"}, {"2001:4860:4860::8844", "2606:4700:4700::1111"}, {"2001:4860:4860::8844", "1.1.1.1"}, {"8.8.4.4", "2606:4700:4700::1111"}} {
		t.Run(pair[0]+"-"+pair[1], func(t *testing.T) {
			addresses := []netip.Addr{netip.MustParseAddr(pair[0]), netip.MustParseAddr(pair[1])}
			a := &ProxyTunnelAdapter{Timeout: time.Second, Resolver: func(context.Context, string) ([]netip.Addr, error) { return addresses, nil }}
			var dialed []netip.AddrPort
			a.nodeEndpointDial = func(c context.Context, endpoint netip.AddrPort) error {
				deadline, finite := c.Deadline()
				if !finite || time.Until(deadline) > time.Second || endpoint.Port() != 443 {
					t.Fatal("unbounded or changed endpoint dial")
				}
				dialed = append(dialed, endpoint)
				if endpoint.Addr() == addresses[0] {
					return errors.New("first endpoint unavailable")
				}
				return nil
			}
			selected, err := a.selectScopedNodeEndpoint(context.Background(), "node.example", 443)
			if err != nil || selected != addresses[1] || !reflect.DeepEqual(dialed, []netip.AddrPort{netip.AddrPortFrom(addresses[0], 443), netip.AddrPortFrom(addresses[1], 443)}) {
				t.Fatal("transport success pinned another address", selected, err, dialed)
			}
		})
	}
}

func TestScopedNodeEndpointSelectionRefusesBeforeDialOrAfterRevocation(t *testing.T) {
	for _, mode := range []string{"private-mix", "mapped-private-mix", "invalid-mix", "zoned-ipv6", "too-many", "scope-negative", "canceled-before", "canceled-resolve", "canceled-dial", "revoked-dial", "all-failed", "budget"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			addresses := []netip.Addr{netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("1.1.1.1")}
			switch mode {
			case "private-mix":
				addresses[1] = netip.MustParseAddr("192.168.1.1")
			case "mapped-private-mix":
				addresses[1] = netip.MustParseAddr("::ffff:192.168.1.1")
			case "invalid-mix":
				addresses[1] = netip.Addr{}
			case "zoned-ipv6":
				addresses[1] = netip.MustParseAddr("2001:4860:4860::8888%eth0")
			case "too-many":
				addresses = make([]netip.Addr, 17)
				for i := range addresses {
					addresses[i] = netip.MustParseAddr("8.8.4.4")
				}
			case "canceled-before":
				cancel()
			}
			resolved, dialed, revoked := 0, 0, false
			ctx = WithNodeResourceGuard(ctx, func(_ context.Context, _ string, address netip.Addr) error {
				if revoked || mode == "scope-negative" && address == addresses[1] {
					return ErrNodeResourceDenied
				}
				return nil
			})
			a := &ProxyTunnelAdapter{Timeout: time.Second}
			if mode == "budget" {
				a.Timeout = 10 * time.Millisecond
			}
			a.Resolver = func(context.Context, string) ([]netip.Addr, error) {
				resolved++
				if mode == "canceled-resolve" {
					cancel()
				}
				return addresses, nil
			}
			a.nodeEndpointDial = func(c context.Context, _ netip.AddrPort) error {
				dialed++
				switch mode {
				case "canceled-dial":
					cancel()
				case "revoked-dial":
					revoked = true
				case "budget":
					<-c.Done()
					return c.Err()
				case "all-failed":
					return errors.New("endpoint unavailable")
				}
				return nil
			}
			selected, err := a.selectScopedNodeEndpoint(ctx, "node.example", 443)
			if err == nil || selected.IsValid() {
				t.Fatal("uncertain endpoint became a pin", mode, selected, err)
			}
			wantDials := 0
			switch mode {
			case "canceled-dial", "revoked-dial", "budget":
				wantDials = 1
			case "all-failed":
				wantDials = 2
			}
			if dialed != wantDials || mode == "canceled-before" && resolved != 0 {
				t.Fatal("partial DNS admission or revocation contacted another endpoint", mode, resolved, dialed)
			}
			if mode == "all-failed" && !errors.Is(err, nodequality.ErrEndpoint) || mode == "scope-negative" && !errors.Is(err, ErrNodeResourceDenied) || mode == "revoked-dial" && !errors.Is(err, ErrNodeResourceDenied) || mode == "budget" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("endpoint refusal lost its cause", mode, err)
			}
		})
	}
}

func TestScopedNodeLiteralEndpointDoesNotGainDNSOrTransportWork(t *testing.T) {
	a := &ProxyTunnelAdapter{
		Resolver: func(context.Context, string) ([]netip.Addr, error) {
			t.Fatal("literal server was resolved")
			return nil, nil
		},
		nodeEndpointDial: func(context.Context, netip.AddrPort) error {
			t.Fatal("literal server gained transport selection")
			return nil
		},
	}
	for _, literal := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		selected, err := a.selectScopedNodeEndpoint(context.Background(), literal, 443)
		if err != nil || selected != netip.MustParseAddr(literal) {
			t.Fatal("literal pin changed", err)
		}
	}
}

func TestScopedXrayStageBindsSelectedEndpointWithoutChangingTLS(t *testing.T) {
	f := scopedXrayTestFixture(t)
	first, second := netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("1.1.1.1")
	f.a.Resolver = func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{first, second}, nil }
	materializer := f.a.NodeRoutes
	var original map[string]any
	f.a.NodeRoutes = func(c context.Context, requests []NodeRouteRequest, profile string, now time.Time) (NodeRouteMaterial, error) {
		material, err := materializer(c, requests, profile, now)
		if err == nil {
			err = json.Unmarshal(material.Config, &original)
		}
		return material, err
	}
	var dialed []netip.Addr
	f.a.nodeEndpointDial = func(_ context.Context, endpoint netip.AddrPort) error {
		dialed = append(dialed, endpoint.Addr())
		if endpoint.Addr() == first {
			return errors.New("first DNS answer unavailable")
		}
		return nil
	}
	data, _, manifest, err := f.a.stageScopedXray(context.Background(), f.plan)
	if err != nil {
		t.Fatal(err)
	}
	var staged map[string]any
	if json.Unmarshal(data, &staged) != nil || !reflect.DeepEqual(dialed, []netip.Addr{first, second}) || len(manifest.Endpoints) != 1 || manifest.Endpoints[0].Host != "node.example" || manifest.Endpoints[0].IP != second.String() {
		t.Fatal("stage did not bind the selected DNS endpoint", err, dialed)
	}
	before := original["outbounds"].([]any)[1].(map[string]any)
	after := staged["outbounds"].([]any)[1].(map[string]any)
	server := after["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	if server["address"] != second.String() || !reflect.DeepEqual(before["streamSettings"], after["streamSettings"]) || !reflect.DeepEqual(before["tag"], after["tag"]) {
		t.Fatal("stage changed TLS/SNI/transport or pinned another address")
	}
	if len(f.processes.startSpecs) != 0 {
		t.Fatal("endpoint transport selection started a process or substituted for canary")
	}
}

func TestScopedXrayStageSharesOneEndpointSelectionDeadline(t *testing.T) {
	f := scopedXrayTestFixture(t)
	ctx := context.Background()
	now := time.Now()
	snapshot, err := f.store.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174001@second.example:443?security=tls&sni=second-front.example", now, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range snapshot.Nodes {
		if node.ID == f.plan.Routes[0].Selected[len("xray:"):] {
			continue
		}
		if _, err := f.store.RecordCheck(ctx, node.ID, nodestore.CheckRecord{ProbeID: "second-unit-pass", ServiceID: "telegram-second", NetworkProfile: executionNetwork, RoutePathID: "xray:" + node.ID, TestLevel: "service", Stage: "service", Verdict: "PASS", State: "available", CheckedAt: now, ExpiresAt: now.Add(time.Hour)}, now); err != nil {
			t.Fatal(err)
		}
		route := f.plan.Routes[0]
		route.ServiceID, route.Selected, route.Resolved, route.CIDRs = "telegram-second", "xray:"+node.ID, "xray:"+node.ID, []string{"9.9.9.9/32"}
		f.plan.Routes = append(f.plan.Routes, route)
	}
	var deadlines []time.Time
	f.a.nodeEndpointDial = func(c context.Context, _ netip.AddrPort) error {
		deadline, finite := c.Deadline()
		if !finite {
			t.Fatal("outbound selection has no total deadline")
		}
		deadlines = append(deadlines, deadline)
		return nil
	}
	if _, _, _, err := f.a.stageScopedXray(ctx, f.plan); err != nil {
		t.Fatal(err)
	}
	if len(deadlines) != 2 || !deadlines[0].Equal(deadlines[1]) {
		t.Fatal("stage renewed a full selection budget for each outbound", deadlines)
	}
}

func TestScopedXrayStageMappedEndpointRevalidates(t *testing.T) {
	for _, literal := range []bool{false, true} {
		t.Run(map[bool]string{false: "dns", true: "literal"}[literal], func(t *testing.T) {
			f := scopedXrayTestFixture(t)
			f.endpoint = netip.MustParseAddr("::ffff:8.8.4.4")
			if literal {
				materializer := f.a.NodeRoutes
				f.a.NodeRoutes = func(c context.Context, requests []NodeRouteRequest, profile string, now time.Time) (NodeRouteMaterial, error) {
					material, err := materializer(c, requests, profile, now)
					if err != nil {
						return material, err
					}
					var doc map[string]any
					if err := json.Unmarshal(material.Config, &doc); err != nil {
						return material, err
					}
					server := doc["outbounds"].([]any)[1].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
					server["address"] = f.endpoint.String()
					material.Config, err = json.Marshal(doc)
					material.EndpointHosts = []string{f.endpoint.String()}
					return material, err
				}
			}
			data, _, manifest, err := f.a.stageScopedXray(context.Background(), f.plan)
			if err != nil || len(manifest.Endpoints) != 1 || manifest.Endpoints[0].IP != "8.8.4.4" {
				t.Fatal("mapped endpoint was not canonically staged", err)
			}
			candidate, _, err := f.a.buildEngineCandidate(data, f.a.SOCKSPort)
			if err != nil {
				t.Fatal(err)
			}
			sidecar := []byte(`{}`)
			manifest.ConfigHash, manifest.SidecarHash = routeidentity.Hash(candidate), routeidentity.Hash(sidecar)
			manifestData, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			manifestPath, enginePath, sidecarPath := filepath.Join(root, "nodes.json"), filepath.Join(root, "engine.json"), filepath.Join(root, "sidecar.json")
			for path, contents := range map[string][]byte{manifestPath: manifestData, enginePath: candidate, sidecarPath: sidecar} {
				if err := os.WriteFile(path, contents, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.a.validateNodeFiles(context.Background(), manifestPath, enginePath, sidecarPath); err != nil {
				t.Fatal("canonical mapped endpoint lost fresh membership", err)
			}
			// Existing manifests may retain the mapped spelling. Config binding
			// remains exact, while fresh address membership is canonical.
			var oldDocument map[string]any
			if err := json.Unmarshal(candidate, &oldDocument); err != nil {
				t.Fatal(err)
			}
			oldServer := oldDocument["outbounds"].([]any)[1].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
			oldServer["address"] = f.endpoint.String()
			candidate, err = json.Marshal(oldDocument)
			if err != nil {
				t.Fatal(err)
			}
			manifest.Endpoints[0].IP, manifest.ConfigHash = f.endpoint.String(), routeidentity.Hash(candidate)
			manifestData, err = json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			for path, contents := range map[string][]byte{manifestPath: manifestData, enginePath: candidate} {
				if err := os.WriteFile(path, contents, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.a.validateNodeFiles(context.Background(), manifestPath, enginePath, sidecarPath); err != nil {
				t.Fatal("existing mapped manifest lost fresh membership", err)
			}
		})
	}
}
