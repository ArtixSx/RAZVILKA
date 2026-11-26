package dataplane

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestProxyCIDRProbeRejectsCompleteSetBeforeCandidateIO(t *testing.T) {
	allowed := netip.MustParseAddr("8.8.8.8")
	denied := netip.MustParseAddr("9.9.9.9")
	for _, tc := range []struct {
		name, engine, url string
		pins              []netip.Addr
		second            bool
	}{
		{"excluded-literal", "sing-box", "https://9.9.9.9/", []netip.Addr{denied}, false},
		{"one-excluded-pin", "sing-box", "https://example.com/", []netip.Addr{allowed, denied}, false},
		{"later-route-excluded", "sing-box", "https://example.com/", []netip.Addr{allowed}, true},
		{"generic-xray-excluded-literal", "xray", "https://9.9.9.9/", []netip.Addr{denied}, false},
		{"generic-xray-one-excluded-pin", "xray", "https://example.com/", []netip.Addr{allowed, denied}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, processes, _ := networkCleanupProxy(t)
			if tc.engine == "xray" {
				var err error
				a, err = NewProxyTunnelAdapter("xray", a.Configs, a.StateRoot)
				if err != nil {
					t.Fatal(err)
				}
				a.Processes = processes
			}
			calls := 0
			a.SOCKSProbe = func(context.Context, string) error { calls++; return nil }
			a.CanaryProbe = func(context.Context, string, string) error { calls++; return nil }
			a.ServiceIPProbe = func(context.Context, string, string, netip.Addr) error { calls++; return nil }
			a.Resolver = func(_ context.Context, host string) ([]netip.Addr, error) {
				if host == denied.String() {
					return []netip.Addr{denied}, nil
				}
				return tc.pins, nil
			}
			route := Route{ServiceID: "network-service", ServiceName: "service", Resolved: tc.engine, ProbeURL: tc.url,
				NetworkPolicyGeneration: strings.Repeat("a", 64), NetworkPolicyRole: "override", Ingress: []string{"br0"},
				Sources: []string{"192.168.1.0/24"}, CIDRs: []string{"8.8.8.8/32"}}
			plan := RoutePlan{Routes: []Route{route}}
			if tc.second {
				other := route
				other.ServiceID, other.ProbeURL = "later-service", "https://9.9.9.9/"
				plan.Routes = append(plan.Routes, other)
			}
			root := t.TempDir()
			spec := a.engineProcessAt(filepath.Join(root, "engine.json"), 19081, root, "sing-box-canary", usqueTransport{})
			if _, err := a.runCanaryAttempt(context.Background(), plan, spec, "127.0.0.1:19081"); !errors.Is(err, ErrNodeResourceDenied) {
				t.Fatal("excluded probe set acquired candidate authority", err)
			}
			if calls != 0 || len(processes.startSpecs) != 0 {
				t.Fatal("probe or process started before complete admission", calls, processes.startSpecs)
			}
			if err := a.probeNodeServiceIP(context.Background(), plan.Routes[len(plan.Routes)-1], "127.0.0.1:18081"); !errors.Is(err, ErrNodeResourceDenied) || calls != 0 {
				t.Fatal("live service probe escaped its reviewed CIDRs", err, calls)
			}
		})
	}
}

func TestProxyCIDRProbeClosesReviewAfterResolver(t *testing.T) {
	a, processes, _ := networkCleanupProxy(t)
	revoked := false
	a.Resolver = func(context.Context, string) ([]netip.Addr, error) {
		revoked = true
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	ctx := WithReviewGuard(context.Background(), func(context.Context) error {
		if revoked {
			return ErrReviewChanged
		}
		return nil
	})
	route := Route{ProbeURL: "https://example.com/", CIDRs: []string{"8.8.8.8/32"}, NetworkPolicyGeneration: strings.Repeat("a", 64)}
	root := t.TempDir()
	spec := a.engineProcessAt(filepath.Join(root, "engine.json"), 19081, root, "sing-box-canary", usqueTransport{})
	if _, err := a.runCanaryAttempt(ctx, RoutePlan{Routes: []Route{route}}, spec, "127.0.0.1:19081"); !errors.Is(err, ErrReviewChanged) || len(processes.startSpecs) != 0 {
		t.Fatal("resolver revoked review but candidate started", err, processes.startSpecs)
	}
}

func TestProxyCIDRProbeNegativeRevocationStopsRemainingPins(t *testing.T) {
	a, _, _ := networkCleanupProxy(t)
	a.Resolver = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.8.9")}, nil
	}
	denied, calls := false, 0
	ctx := WithNodeResourceGuard(context.Background(), func(context.Context, string, netip.Addr) error {
		if denied {
			return ErrNodeResourceDenied
		}
		return nil
	})
	a.ServiceIPProbe = func(context.Context, string, string, netip.Addr) error {
		calls++
		denied = true
		return nil
	}
	route := Route{ProbeURL: "https://example.com/", CIDRs: []string{"8.8.8.0/24"}, NetworkPolicyGeneration: strings.Repeat("a", 64)}
	if err := a.probeNodeServiceIP(ctx, route, "127.0.0.1:18081"); !errors.Is(err, ErrNodeResourceDenied) || calls != 1 {
		t.Fatal("successful old probe hid revocation or allowed the next pin", err, calls)
	}
}

func TestScopedXrayCIDRHostnameCanaryRetainsPinnedTLSHostAndAcceptance(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			hosts := make(chan string, 1)
			paths := make(chan string, 1)
			backend, roots, names := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
				hosts <- r.Host
				paths <- r.URL.RequestURI()
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "service reached")
			})
			socks := newPinnedSOCKSFixture(t, backend.Listener.Addr().String(), false)
			f := scopedXrayTestFixture(t)
			_, port, _ := net.SplitHostPort(socks.address)
			number, _ := strconv.Atoi(port)
			f.a.SOCKSPort = number - 1000
			rawURL := "https://example.com/health?q=original"
			f.plan.Routes[0].Domains = nil
			f.plan.Routes[0].CIDRs = []string{"8.8.8.8/32"}
			f.plan.Routes[0].ProbeURL = rawURL
			f.a.CanaryProbe = func(context.Context, string, string) error {
				t.Fatal("CIDR-only Xray sent an opaque hostname before its literal")
				return nil
			}
			f.a.ServiceIPProbe = func(ctx context.Context, url, address string, pin netip.Addr) error {
				if url != rawURL || address != socks.address || pin.String() != "8.8.8.8" {
					t.Fatal("canary changed original target or admitted literal", url, address, pin)
				}
				response, cleanup, err := socksHTTPGetPinnedTLS(ctx, url, address, pin, roots)
				if err != nil {
					return err
				}
				defer cleanup()
				defer response.Body.Close()
				_, err = strictServiceResponse(url, response)
				return err
			}
			root := privateScopedXrayFixtureDir(t)
			for _, prepare := range []func(context.Context, Plan, string) error{f.a.Snapshot, f.a.Stage, f.a.Validate} {
				if err := prepare(context.Background(), f.plan, root); err != nil {
					t.Fatal(err)
				}
			}
			err := f.a.Canary(context.Background(), RoutePlan{NetworkProfileID: f.plan.NetworkProfileID, Routes: f.plan.Routes}, root)
			if status == http.StatusOK && err != nil || status == http.StatusForbidden && err == nil {
				t.Fatal("canary lost service acceptance semantics", status, err)
			}
			var request pinnedSOCKSRequest
			select {
			case request = <-socks.requests:
			case <-time.After(time.Second):
				t.Fatal("canary did not send a pinned CONNECT", err)
			}
			if request.AddressType != 1 || request.Host != "8.8.8.8" || request.Port != 443 || len(socks.requests) != 0 {
				t.Fatal("canary used an unpinned or repeated CONNECT", request)
			}
			var host, sni, path string
			for _, observation := range []struct {
				channel <-chan string
				value   *string
			}{{hosts, &host}, {names, &sni}, {paths, &path}} {
				select {
				case *observation.value = <-observation.channel:
				case <-time.After(time.Second):
					t.Fatal("canary did not reach the verified TLS service", err)
				}
			}
			if host != "example.com" || sni != "example.com" || path != "/health?q=original" {
				t.Fatal("original Host or verified TLS SNI changed", host, sni)
			}
			if f.processes.running["xray-canary"] {
				t.Fatal("candidate remained running after probe")
			}
		})
	}
}

// A legacy exact-node CIDR ruleset rejects SOCKS hostnames. The canary must
// exercise its admitted IP path first without adding domain permissions.
func TestLegacyExactNodeCIDRCanaryPinnedTLS(t *testing.T) {
	for _, engine := range []string{"sing-box", "xray"} {
		for _, scenario := range []string{"accepted", "http-rejected", "certificate-rejected", "outside-cidr"} {
			t.Run(engine+"/"+scenario, func(t *testing.T) {
				backend, roots, names := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
					if r.Host != "example.com" || r.URL.RequestURI() != "/health?q=original" {
						t.Error("original HTTP identity changed")
					}
					w.Header().Set("Content-Type", "text/plain")
					if scenario == "http-rejected" {
						w.WriteHeader(http.StatusForbidden)
					}
					_, _ = io.WriteString(w, "service reached")
				})
				socks := newPinnedSOCKSFixture(t, backend.Listener.Addr().String(), false)
				a, processes, _ := networkCleanupProxy(t)
				if engine == "xray" {
					var err error
					a, err = NewProxyTunnelAdapter(engine, a.Configs, a.StateRoot)
					if err != nil {
						t.Fatal(err)
					}
					a.Processes = processes
				}
				a.SOCKSProbe = func(context.Context, string) error { return nil }
				opaqueCalls, ipCalls := 0, 0
				a.CanaryProbe = func(context.Context, string, string) error {
					opaqueCalls++
					return errors.New("SOCKS hostname denied by CIDR ruleset")
				}
				a.Resolver = func(context.Context, string) ([]netip.Addr, error) {
					pins := []netip.Addr{netip.MustParseAddr("8.8.8.8")}
					if scenario == "outside-cidr" {
						pins = append(pins, netip.MustParseAddr("9.9.9.9"))
					}
					return pins, nil
				}
				a.ServiceIPProbe = func(ctx context.Context, rawURL, address string, pin netip.Addr) error {
					ipCalls++
					if rawURL != "https://example.com/health?q=original" || address != socks.address || pin.String() != "8.8.8.8" {
						t.Fatal("canary changed admitted target")
					}
					if scenario == "certificate-rejected" {
						roots = nil
					}
					response, cleanup, err := socksHTTPGetPinnedTLS(ctx, rawURL, address, pin, roots)
					if cleanup != nil {
						defer cleanup()
					}
					if err != nil {
						return err
					}
					defer response.Body.Close()
					_, err = strictServiceResponse(rawURL, response)
					return err
				}
				route := Route{ServiceID: "telegram-ip", ServiceName: "Telegram IP", Resolved: engine + ":node-" + strings.Repeat("a", 64), ProbeURL: "https://example.com/health?q=original", CIDRs: []string{"8.8.8.8/32"}}
				root := t.TempDir()
				spec := a.engineProcessAt(filepath.Join(root, "engine.json"), 19081, root, engine+"-canary", usqueTransport{})
				result, err := a.runCanaryAttempt(context.Background(), RoutePlan{Routes: []Route{route}}, spec, socks.address)
				if (err == nil) != (scenario == "accepted") {
					t.Fatal("canary changed service acceptance", scenario, err)
				}
				if opaqueCalls != 0 {
					t.Fatal("CIDR-only node sent hostname to SOCKS", opaqueCalls)
				}
				if scenario == "outside-cidr" {
					if ipCalls != 0 || len(processes.startSpecs) != 0 || !errors.Is(err, ErrNodeResourceDenied) {
						t.Fatal("outside-CIDR DNS started candidate", err)
					}
					return
				}
				if ipCalls != 1 {
					t.Fatal("missing exact literal probe", ipCalls)
				}
				request := <-socks.requests
				if request.AddressType != 1 || request.Host != "8.8.8.8" || request.Port != 443 {
					t.Fatal("not a pinned IPv4 SOCKS request", request)
				}
				select {
				case name := <-names:
					if name != "example.com" {
						t.Fatal("TLS SNI changed", name)
					}
				case <-time.After(time.Second):
					t.Fatal("no TLS SNI")
				}
				if scenario == "accepted" && len(result.ConfirmedRoutes) != 1 {
					t.Fatal("canary did not confirm service")
				}
				if processes.running[engine+"-canary"] {
					t.Fatal("candidate not cleaned")
				}
			})
		}
	}
}
func TestLegacyNodeIPScopeRequiresExactMatchingCIDROnlyNode(t *testing.T) {
	a, _, _ := networkCleanupProxy(t)
	node := "node-" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, resolved string
		domains, cidrs []string
		want           bool
	}{
		{"exact", "sing-box:" + node, nil, []string{"8.8.8.8/32"}, true},
		{"other-engine", "xray:" + node, nil, []string{"8.8.8.8/32"}, false},
		{"generic", "sing-box", nil, []string{"8.8.8.8/32"}, false},
		{"profile", "sing-box:home", nil, []string{"8.8.8.8/32"}, false},
		{"group", "sing-box:group-" + strings.Repeat("a", 64), nil, []string{"8.8.8.8/32"}, false},
		{"domains", "sing-box:" + node, []string{"example.com"}, []string{"8.8.8.8/32"}, false},
		{"no-cidrs", "sing-box:" + node, nil, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.nodeServiceIPScopeRequired(Route{Resolved: tc.resolved, Domains: tc.domains, CIDRs: tc.cidrs}); got != tc.want {
				t.Fatal("wrong finite scope", got)
			}
		})
	}
}

func TestNodeIPHealthFiniteRouteSkipsOnlyOpaqueProbe(t *testing.T) {
	for _, scenario := range []string{"finite", "domain", "generic", "outside-cidr", "http-rejected", "missing-process"} {
		t.Run(scenario, func(t *testing.T) {
			backend, roots, _ := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "example.com" {
					t.Error("health Host changed")
				}
				w.Header().Set("Content-Type", "text/plain")
				if scenario == "http-rejected" {
					w.WriteHeader(http.StatusForbidden)
				}
				_, _ = io.WriteString(w, "service reached")
			})
			socks := newPinnedSOCKSFixture(t, backend.Listener.Addr().String(), false)
			a, runner, policy := proxyForwardingFixture(t)
			a.Processes = runner.processes
			a.SOCKSProbe = func(context.Context, string) error { return nil }
			a.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
			runner.processes.running["sing-box-engine"], runner.processes.running["sing-box-tun"] = true, true
			if err := a.installForwarding(context.Background(), policy); err != nil {
				t.Fatal(err)
			}
			if scenario == "missing-process" {
				delete(runner.processes.running, "sing-box-engine")
			}
			a.Resolver = func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			}
			opaque, ipCalls := 0, 0
			a.Probe = func(context.Context, string) error { opaque++; return errors.New("opaque health hostname rejected") }
			a.ServiceIPProbe = func(ctx context.Context, raw, address string, pin netip.Addr) error {
				ipCalls++
				response, cleanup, err := socksHTTPGetPinnedTLS(ctx, raw, socks.address, pin, roots)
				if cleanup != nil {
					defer cleanup()
				}
				if err != nil {
					return err
				}
				defer response.Body.Close()
				_, err = strictServiceResponse(raw, response)
				return err
			}
			plan := networkExecutionPlan()
			route := &plan.Routes[0]
			route.Domains = nil
			route.CIDRs = []string{"8.8.8.8/32"}
			route.ProbeURL = "https://example.com/"
			if scenario == "domain" {
				route.Domains = []string{"example.com"}
			}
			if scenario == "generic" {
				route.Resolved = "sing-box"
			}
			if scenario == "outside-cidr" {
				route.CIDRs = []string{"9.9.9.9/32"}
			}
			err := a.healthState(context.Background(), plan, policy)
			if scenario == "finite" {
				if err != nil || ipCalls != 1 || opaque != 0 {
					t.Fatal("finite health fell through after pinned success", err, ipCalls, opaque)
				}
			} else if err == nil {
				t.Fatal("health incorrectly passed", scenario)
			}
			if (scenario == "domain" || scenario == "generic") && opaque != 1 {
				t.Fatal("nonfinite opaque health was skipped", scenario, opaque)
			}
			if (scenario == "outside-cidr" || scenario == "missing-process") && (ipCalls != 0 || opaque != 0) {
				t.Fatal("health probe preceded guard", scenario, ipCalls, opaque)
			}
		})
	}
}
