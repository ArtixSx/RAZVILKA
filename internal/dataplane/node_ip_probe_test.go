package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

func TestNodeServiceIPv4RejectsUnsafeOrUnboundedDNS(t *testing.T) {
	for _, values := range [][]string{
		nil, {"127.0.0.1"}, {"93.184.216.34", "192.168.1.1"}, {"93.184.216.34", "fd00::1"}, {"2606:4700::1111"},
		{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"},
	} {
		addresses := make([]netip.Addr, 0, len(values))
		for _, value := range values {
			addresses = append(addresses, netip.MustParseAddr(value))
		}
		resolver := func(context.Context, string) ([]netip.Addr, error) { return addresses, nil }
		if got, err := resolveNodeServiceIPv4(context.Background(), "https://telegram.org/", resolver); err == nil || len(got) > 0 {
			t.Fatalf("unsafe set %v accepted: %v %v", values, got, err)
		}
	}
}

func TestExactNodeDomainSuccessDoesNotGrantIPPathAuthority(t *testing.T) {
	for _, fail := range []string{"unsupported", "wrong-route", "private-dns", "second-ip"} {
		t.Run(fail, func(t *testing.T) {
			checker := fakeExactNodeChecker(t)
			checker.resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
				if host == "node.example" {
					return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
				}
				if fail == "private-dns" {
					return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("192.168.1.1")}, nil
				}
				return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("93.184.216.35")}, nil
			}
			base := checker.serviceIPProbe
			calls, cleaned := 0, false
			checker.serviceIPProbe = func(ctx context.Context, address, route, egress string, service catalog.Service, pinned netip.Addr) (evidence.ProbeEvidence, error) {
				calls++
				proof, err := base(ctx, address, route, egress, service, pinned)
				switch fail {
				case "unsupported":
					return proof, errors.New("domain works but literal IP transport failed")
				case "wrong-route":
					proof.ObservedRoutePathID = "another-route"
				case "second-ip":
					if calls == 2 {
						return proof, errors.New("second destination failed")
					}
				}
				return proof, err
			}
			checker.cleanup = func(context.Context, exactNodeSession) error { cleaned = true; return nil }
			result, err := checker.Check(context.Background(), checkedNodeRequest())
			if err != nil || result.Available || result.Verdict == evidence.VerdictPass || result.Evidence.Verdict == evidence.VerdictPass || result.Stage != "service_ip" || !cleaned {
				t.Fatalf("IP failure gained authority: %+v err=%v cleaned=%t", result, err, cleaned)
			}
			if fail == "private-dns" && calls != 0 || fail == "second-ip" && calls != 2 {
				t.Fatalf("IP set admission did not fail closed: calls=%d", calls)
			}
		})
	}
}

func TestExactNodeCanceledIPProbeCleansBeforeReleasingRuntime(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cleaned := false
	checker.serviceIPProbe = func(context.Context, string, string, string, catalog.Service, netip.Addr) (evidence.ProbeEvidence, error) {
		cancel()
		return evidence.ProbeEvidence{}, context.Canceled
	}
	checker.cleanup = func(cleanupCtx context.Context, _ exactNodeSession) error {
		if cleanupCtx.Err() != nil {
			t.Fatal("IP probe cancellation canceled cleanup")
		}
		if _, bounded := cleanupCtx.Deadline(); !bounded {
			t.Fatal("IP probe cleanup is unbounded")
		}
		cleaned = true
		return nil
	}
	result, err := checker.Check(ctx, checkedNodeRequest())
	if err == nil || result.Available || result.Verdict == evidence.VerdictPass || !cleaned || len(checker.gate) != 0 {
		t.Fatalf("cancel lost isolation: available=%t cleaned=%t err=%v", result.Available, cleaned, err)
	}
}

type nodeIPCanaryAdapter struct {
	*fakeAdapter
	proxy        *ProxyTunnelAdapter
	healthPolicy *PolicyState
}

func (a *nodeIPCanaryAdapter) Stage(ctx context.Context, _ Plan, root string) error {
	if err := a.call("stage"); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "engine.staged.json"), []byte(`{"inbounds":[],"outbounds":[{"type":"vless","server":"node.example","server_port":443}]}`), 0o600)
}

func (a *nodeIPCanaryAdapter) Canary(ctx context.Context, plan RoutePlan, root string) error {
	return a.proxy.Canary(ctx, plan, root)
}

func (a *nodeIPCanaryAdapter) Health(ctx context.Context, plan Plan, _ string) error {
	if err := a.call("health"); err != nil {
		return err
	}
	if a.healthPolicy != nil {
		return a.proxy.healthState(ctx, plan, *a.healthPolicy)
	}
	return nil
}

func TestNodeIPCanaryFailurePreservesWorkingRuntimeBeforeActivate(t *testing.T) {
	proxy, processes, _ := networkCleanupProxy(t)
	processes.running["sing-box-engine"], processes.running["sing-box-tun"], processes.running["unrelated"] = true, true, true
	domainCalls, ipCalls := 0, 0
	proxy.CanaryProbe = func(context.Context, string, string) error { domainCalls++; return nil }
	proxy.ServiceIPProbe = func(_ context.Context, url, address string, pinned netip.Addr) error {
		ipCalls++
		if url != "https://telegram.org/" || !strings.HasSuffix(address, ":19081") || !pinned.Is4() {
			t.Fatal("IP canary did not use exact isolated transport")
		}
		return errors.New("literal IP unavailable")
	}
	manager := New(t.TempDir())
	manager.FreshProfile = proxy.FreshProfile
	adapter := &nodeIPCanaryAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}, proxy: proxy}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	execution, err := manager.Apply(context.Background(), networkExecutionPlan(), nil)
	if err == nil || execution.State != "canary-failed" || domainCalls != 1 || ipCalls != 1 || adapter.rollback || strings.Contains(strings.Join(adapter.calls, ","), "activate") {
		t.Fatalf("domain-only canary activated runtime: state=%s calls=%v err=%v", execution.State, adapter.calls, err)
	}
	if len(processes.running) != 3 || !processes.running["sing-box-engine"] || !processes.running["sing-box-tun"] || !processes.running["unrelated"] {
		t.Fatalf("isolated failure touched existing processes: %v", processes.running)
	}
}

func TestNodeIPHealthChecksDeviceScopedRoutes(t *testing.T) {
	proxy, runner, policy := proxyForwardingFixture(t)
	processes := runner.processes
	proxy.Processes = processes
	proxy.SOCKSProbe = func(context.Context, string) error { return nil }
	proxy.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
	proxy.Resolver = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	processes.running["sing-box-engine"], processes.running["sing-box-tun"] = true, true
	if err := proxy.installForwarding(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	plan := networkExecutionPlan()
	plan.Routes[0].Sources = []string{"192.168.1.25/32"}
	ipCalls := 0
	proxy.ServiceIPProbe = func(_ context.Context, _, address string, _ netip.Addr) error {
		ipCalls++
		if !strings.HasSuffix(address, ":18081") {
			t.Fatal("live health used a different SOCKS channel")
		}
		return errors.New("IP path failed after activation")
	}
	if err := proxy.healthState(context.Background(), plan, policy); err == nil || ipCalls != 1 {
		t.Fatalf("device-scoped live IP health was skipped: calls=%d err=%v", ipCalls, err)
	}
	// The same failure after Activate must enter the ordinary rollback path.
	proxy.EngineBin = "sing-box"
	proxy.CanaryProbe = func(context.Context, string, string) error { return nil }
	proxy.ServiceIPProbe = func(_ context.Context, _, address string, _ netip.Addr) error {
		if strings.HasSuffix(address, ":19081") {
			return nil
		}
		return errors.New("IP path failed only after activation")
	}
	manager := New(t.TempDir())
	manager.FreshProfile = proxy.FreshProfile
	adapter := &nodeIPCanaryAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}, proxy: proxy, healthPolicy: &policy}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	execution, err := manager.Apply(context.Background(), plan, nil)
	if err == nil || execution.State != "rolled-back" || !adapter.rollback || !strings.Contains(strings.Join(adapter.calls, ","), "activate") {
		t.Fatalf("post-Activate IP failure did not roll back: state=%s calls=%v err=%v", execution.State, adapter.calls, err)
	}
}
