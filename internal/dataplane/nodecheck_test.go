package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

const checkedNodeID = "node-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func fakeExactNodeChecker(t *testing.T) *ExactNodeChecker {
	t.Helper()
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	checker := NewExactNodeChecker(t.TempDir())
	checker.egressPair = nil // Legacy field fixtures isolate individual checker gates.
	checker.now = func() time.Time { now = now.Add(time.Millisecond); return now }
	checker.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.8")}, nil
	}
	checker.dialTransport = func(context.Context, exactNodeEndpoint, []netip.Addr) (bool, error) { return true, nil }
	checker.prepare = func(context.Context, NodeCheckRequest, exactNodeEndpoint) (exactNodeSession, error) {
		return exactNodeSession{Address: "127.0.0.1:19181", Spec: ProcessSpec{Binary: "sing-box"}}, nil
	}
	checker.start = func(context.Context, exactNodeSession) error { return nil }
	checker.identity = func(exactNodeSession) (routeidentity.Passport, error) {
		return routeidentity.Passport{ID: "managed:sing-box:test", Outbound: "vless", PID: 42}, nil
	}
	checker.directEgress = func(context.Context) (string, error) { return "198.51.100.10", nil }
	checker.proxyEgress = func(context.Context, string) (string, error) { return "2001:db8::20", nil }
	checker.serviceProbe = func(context.Context, string, string, string, catalog.Service) (evidence.ProbeEvidence, error) {
		return evidence.ProbeEvidence{
			SchemaVersion: evidence.ProbeSchemaVersion, ProbeID: "service-proof", StartedAt: now,
			FinishedAt: now.Add(time.Millisecond), Service: "telegram", RoutePathID: "sing-box:" + checkedNodeID,
			ExpectedRoutePathID: "sing-box:" + checkedNodeID, ObservedRoutePathID: "sing-box:" + checkedNodeID,
			Outcome: evidence.OutcomeServiceAccepted, Verdict: evidence.VerdictPass, HTTPStatus: 204,
		}, nil
	}
	baseServiceProof := checker.serviceProbe
	checker.serviceIPProbe = func(ctx context.Context, address, route, egress string, service catalog.Service, _ netip.Addr) (evidence.ProbeEvidence, error) {
		return baseServiceProof(ctx, address, route, egress, service)
	}
	checker.cleanup = func(context.Context, exactNodeSession) error { return nil }
	checker.runtimeReady = func() bool { return true }
	checker.FreshProfile = func(context.Context) (string, error) { return "wan-0123456789ab", nil }
	return checker
}

func checkedNodeRequest() NodeCheckRequest {
	return NodeCheckRequest{
		NodeID: checkedNodeID, NetworkProfile: "wan-0123456789ab",
		Outbound: []byte(`{"type":"vless","server":"node.example","server_port":443,"uuid":"private"}`),
		Service:  catalog.Service{ID: "telegram", ProbeURL: "https://telegram.org/", Strategy: []string{"sing-box"}},
	}
}

func TestExactNodeCheckConfirmsExactServicePath(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	result, err := checker.Check(context.Background(), checkedNodeRequest())
	if err != nil || !result.Available || result.Verdict != evidence.VerdictPass || result.TestLevel != "service" || result.EgressIP != "2001:db8::20" || result.DirectLeak {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if result.Evidence.NetworkProfile != "wan-0123456789ab" || result.Evidence.AssuranceLevel() != evidence.Service || len(result.Stages) != 8 {
		t.Fatalf("evidence=%+v stages=%+v", result.Evidence, result.Stages)
	}
}

func TestExactNodeCheckRejectsDirectLeak(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	checker.directEgress = func(context.Context) (string, error) { return "2001:0db8:0:0:0:0:0:20", nil }
	result, err := checker.Check(context.Background(), checkedNodeRequest())
	if err != nil || result.Available || !result.DirectLeak || result.Verdict != evidence.VerdictMisrouted || result.ErrorCode != "node-direct-leak" || result.TestLevel != "egress" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	encoded, err := json.Marshal(result)
	if err != nil || result.EgressIP != "" || strings.Contains(string(encoded), "2001:db8::20") {
		t.Fatal("direct egress address escaped into the public check result")
	}
}

func TestExactNodeCheckDoesNotPromoteOpenTCPPort(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	checker.proxyEgress = func(context.Context, string) (string, error) { return "", errors.New("wrong uuid") }
	result, err := checker.Check(context.Background(), checkedNodeRequest())
	if err != nil || result.Available || result.TestLevel != "protocol" || result.ErrorCode != "node-egress-failed" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	for _, stage := range result.Stages {
		if stage.ID == "service" {
			t.Fatal("service stage ran after failed protocol")
		}
	}
}

func TestExactNodeCheckReturnsOnlyBoundedIdentityDiagnostic(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	checker.identity = func(exactNodeSession) (routeidentity.Passport, error) {
		return routeidentity.Passport{}, errors.New("route-listener-owner-mismatch")
	}
	result, err := checker.Check(context.Background(), checkedNodeRequest())
	if err != nil || result.Available || result.ErrorCode != "node-route-listener-owner-mismatch" {
		t.Fatalf("result=%+v err=%v", result, err)
	}

	checker = fakeExactNodeChecker(t)
	checker.identity = func(exactNodeSession) (routeidentity.Passport, error) {
		return routeidentity.Passport{}, errors.New("private endpoint node.example with secret")
	}
	result, err = checker.Check(context.Background(), checkedNodeRequest())
	if err != nil || result.ErrorCode != "node-route-identity-failed" || strings.Contains(result.ErrorCode, "secret") {
		t.Fatalf("unbounded diagnostic escaped: %+v %v", result, err)
	}
}

func TestExactNodeCheckRejectsBlockedServiceAndCleanupFailure(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	checker.serviceProbe = func(context.Context, string, string, string, catalog.Service) (evidence.ProbeEvidence, error) {
		now := time.Now().UTC()
		return evidence.ProbeEvidence{SchemaVersion: evidence.ProbeSchemaVersion, StartedAt: now, FinishedAt: now, RoutePathID: "sing-box:" + checkedNodeID, ExpectedRoutePathID: "sing-box:" + checkedNodeID, ObservedRoutePathID: "sing-box:" + checkedNodeID, Outcome: evidence.OutcomeServiceBlocked, Verdict: evidence.VerdictBlocked, HTTPStatus: 451}, nil
	}
	result, err := checker.Check(context.Background(), checkedNodeRequest())
	if err != nil || result.Available || result.Verdict != evidence.VerdictBlocked || result.TestLevel != "service" {
		t.Fatalf("blocked result=%+v err=%v", result, err)
	}

	checker = fakeExactNodeChecker(t)
	checker.cleanup = func(context.Context, exactNodeSession) error { return errors.New("still running") }
	result, err = checker.Check(context.Background(), checkedNodeRequest())
	if err != nil || result.Available || result.Stage != "cleanup" || result.ErrorCode != "node-cleanup-failed" {
		t.Fatalf("cleanup result=%+v err=%v", result, err)
	}
	if _, err := checker.Check(context.Background(), checkedNodeRequest()); !errors.Is(err, ErrExactNodeUnavailable) {
		t.Fatalf("checker was not fenced after cleanup failure: %v", err)
	}
}

func TestExactNodeCheckCleansRejectedRuntimeConfig(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	cleaned := false
	checker.prepare = func(context.Context, NodeCheckRequest, exactNodeEndpoint) (exactNodeSession, error) {
		return exactNodeSession{Root: checker.StateRoot, Address: "127.0.0.1:19181", Spec: ProcessSpec{Binary: "sing-box"}}, errors.New("config rejected")
	}
	checker.cleanup = func(context.Context, exactNodeSession) error {
		cleaned = true
		return nil
	}
	result, err := checker.Check(context.Background(), checkedNodeRequest())
	if err != nil || result.Available || result.ErrorCode != "node-runtime-config-rejected" || !cleaned {
		t.Fatalf("rejected config cleanup result=%+v cleaned=%t err=%v", result, cleaned, err)
	}
}

func TestExactNodeCheckRejectsServiceRouteMismatch(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	checker.serviceProbe = func(context.Context, string, string, string, catalog.Service) (evidence.ProbeEvidence, error) {
		now := time.Now().UTC()
		return evidence.ProbeEvidence{
			SchemaVersion: evidence.ProbeSchemaVersion, ProbeID: "service-proof", StartedAt: now, FinishedAt: now,
			Service: "telegram", RoutePathID: "sing-box:" + checkedNodeID,
			ExpectedRoutePathID: "sing-box:" + checkedNodeID, ObservedRoutePathID: "direct",
			Outcome: evidence.OutcomeServiceAccepted, Verdict: evidence.VerdictPass, HTTPStatus: 200,
		}, nil
	}
	result, err := checker.Check(context.Background(), checkedNodeRequest())
	if err != nil || result.Available || result.Verdict != evidence.VerdictMisrouted || result.ErrorCode != "node-route-mismatch" {
		t.Fatalf("route mismatch result=%+v err=%v", result, err)
	}
}

func TestExactNodeCheckRequiresDirectNegativeControl(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	checker.directEgress = func(context.Context) (string, error) { return "", errors.New("direct unavailable") }
	result, err := checker.Check(context.Background(), checkedNodeRequest())
	if err != nil || result.Available || result.Verdict != evidence.VerdictInconclusive || result.ErrorCode != "node-direct-control-unavailable" || result.TestLevel != "egress" || result.EgressIP != "" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestExactNodeOutboundInspectionIsFailClosed(t *testing.T) {
	for _, raw := range []string{
		`{"type":"wireguard","server":"node.example","server_port":443}`,
		`{"type":"vless","tag":"selected","server":"node.example","server_port":443}`,
		`{"type":"vless","detour":"other","server":"node.example","server_port":443}`,
		`{"type":"vless","server":"127.0.0.1","server_port":443}`,
	} {
		if _, err := inspectExactNodeOutbound([]byte(raw)); err == nil {
			t.Fatalf("unsafe outbound accepted: %s", raw)
		}
	}
}

func TestPinnedNodeAddressPreservesTLSAndWebHost(t *testing.T) {
	var outbound map[string]any
	if err := json.Unmarshal([]byte(`{"type":"vless","server":"edge.example","server_port":443,"tls":{"enabled":true},"transport":{"type":"ws"}}`), &outbound); err != nil {
		t.Fatal(err)
	}
	preserveNodeHostname(outbound, "edge.example")
	if outbound["tls"].(map[string]any)["server_name"] != "edge.example" || outbound["transport"].(map[string]any)["headers"].(map[string]any)["Host"] != "edge.example" {
		t.Fatalf("hostname semantics were not preserved: %+v", outbound)
	}
}

func TestExactNodeCheckerSerializesTemporaryRuntime(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	checker.resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "node.example" {
			close(entered)
			<-release
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.8")}, nil
	}
	done := make(chan error, 1)
	go func() {
		_, err := checker.Check(context.Background(), checkedNodeRequest())
		done <- err
	}()
	<-entered
	if _, err := checker.Check(context.Background(), checkedNodeRequest()); !errors.Is(err, ErrExactNodeBusy) {
		t.Fatalf("parallel checker error=%v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestExactNodeCheckerExplainsMissingRuntime(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	checker.runtimeReady = func() bool { return false }
	if _, err := checker.Check(context.Background(), checkedNodeRequest()); !errors.Is(err, ErrExactNodeRuntime) {
		t.Fatalf("missing runtime error=%v", err)
	}
}

func TestExactNodeCheckerRechecksCleanupFenceAfterAcquiringGate(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	cleanupEntered := make(chan struct{})
	releaseCleanup := make(chan struct{})
	validationEntered := make(chan struct{})
	releaseValidation := make(chan struct{})
	var calls atomic.Int32
	checker.runtimeReady = func() bool {
		if calls.Add(1) == 2 {
			close(validationEntered)
			<-releaseValidation
		}
		return true
	}
	checker.cleanup = func(context.Context, exactNodeSession) error {
		select {
		case <-cleanupEntered:
		default:
			close(cleanupEntered)
		}
		<-releaseCleanup
		return errors.New("temporary process still running")
	}
	first := make(chan error, 1)
	go func() {
		_, err := checker.Check(context.Background(), checkedNodeRequest())
		first <- err
	}()
	<-cleanupEntered
	second := make(chan error, 1)
	go func() {
		_, err := checker.Check(context.Background(), checkedNodeRequest())
		second <- err
	}()
	<-validationEntered
	close(releaseCleanup)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	close(releaseValidation)
	if err := <-second; !errors.Is(err, ErrExactNodeUnavailable) {
		t.Fatalf("request validated before cleanup failure bypassed the fence: %v", err)
	}
}

func TestExactNodeCheckerRecoveryClearsCleanupFence(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	checker.poisoned.Store(true)
	if err := checker.Recover(context.Background()); err != nil || checker.poisoned.Load() {
		t.Fatalf("recovery did not clear cleanup fence: %v", err)
	}
	if result, err := checker.Check(context.Background(), checkedNodeRequest()); err != nil || !result.Available {
		t.Fatalf("checker did not resume after recovery: %+v %v", result, err)
	}
}

func TestExactNodeCheckRejectsUnconfirmedInitialNetwork(t *testing.T) {
	for _, profile := range []string{"", "network-unknown", "legacy-unscoped", "wan-ffffffffffff"} {
		t.Run(profile, func(t *testing.T) {
			checker := fakeExactNodeChecker(t)
			checker.FreshProfile = func(context.Context) (string, error) { return profile, nil }
			checker.resolve = func(context.Context, string) ([]netip.Addr, error) {
				t.Fatal("network mismatch reached node DNS")
				return nil, nil
			}
			if _, err := checker.Check(context.Background(), checkedNodeRequest()); !errors.Is(err, ErrExactNodeNetworkChanged) {
				t.Fatalf("unconfirmed current epoch accepted: %v", err)
			}
		})
	}
	checker := fakeExactNodeChecker(t)
	request := checkedNodeRequest()
	request.NetworkProfile = "network-unknown"
	if _, err := checker.Check(context.Background(), request); !errors.Is(err, ErrExactNodeUnavailable) {
		t.Fatalf("unknown request epoch accepted: %v", err)
	}
}

func TestExactNodeCheckRejectsNetworkChangeDuringProbeOrCleanup(t *testing.T) {
	for _, phase := range []string{"probe", "cleanup", "observation-error"} {
		t.Run(phase, func(t *testing.T) {
			checker := fakeExactNodeChecker(t)
			profile := "wan-0123456789ab"
			var observationErr error
			cleaned := false
			checker.FreshProfile = func(context.Context) (string, error) { return profile, observationErr }
			originalProbe := checker.serviceProbe
			checker.serviceProbe = func(ctx context.Context, address, route, egress string, service catalog.Service) (evidence.ProbeEvidence, error) {
				proof, err := originalProbe(ctx, address, route, egress, service)
				if phase == "probe" {
					profile = "wan-ffffffffffff"
				}
				return proof, err
			}
			checker.cleanup = func(context.Context, exactNodeSession) error {
				cleaned = true
				if phase == "cleanup" {
					profile = "wan-ffffffffffff"
				} else if phase == "observation-error" {
					observationErr = errors.New("private WAN details must not escape")
				}
				return nil
			}
			result, err := checker.Check(context.Background(), checkedNodeRequest())
			if !errors.Is(err, ErrExactNodeNetworkChanged) || !cleaned || result.Available || result.Verdict == evidence.VerdictPass || result.Evidence.Verdict == evidence.VerdictPass || result.EgressIP != "" || result.Evidence.EgressIP != "" {
				t.Fatalf("network change retained proof: result=%+v cleaned=%t err=%v", result, cleaned, err)
			}
			if result.NetworkProfile != "wan-0123456789ab" || result.Evidence.NetworkProfile != "wan-0123456789ab" {
				t.Fatal("old observations were relabelled with a new epoch")
			}
		})
	}
}

func TestExactNodeCheckRechecksNetworkAfterRequestValidation(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	profile := "wan-0123456789ab"
	checker.FreshProfile = func(context.Context) (string, error) { return profile, nil }
	checker.runtimeReady = func() bool {
		profile = "wan-ffffffffffff"
		return true
	}
	checker.resolve = func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("network changed before the gate but node DNS still ran")
		return nil, nil
	}
	if _, err := checker.Check(context.Background(), checkedNodeRequest()); !errors.Is(err, ErrExactNodeNetworkChanged) {
		t.Fatalf("network change during request validation was accepted: %v", err)
	}
}

func TestExactNodeCheckCancellationDoesNotPromoteProofOrSkipCleanup(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	originalProbe := checker.serviceProbe
	checker.serviceProbe = func(ctx context.Context, address, route, egress string, service catalog.Service) (evidence.ProbeEvidence, error) {
		proof, err := originalProbe(ctx, address, route, egress, service)
		cancel()
		return proof, err
	}
	cleaned := false
	checker.cleanup = func(cleanupCtx context.Context, _ exactNodeSession) error {
		cleaned = true
		return cleanupCtx.Err()
	}
	result, err := checker.Check(ctx, checkedNodeRequest())
	if !errors.Is(err, context.Canceled) || !cleaned || checker.poisoned.Load() || result.Available || result.Evidence.Verdict == evidence.VerdictPass {
		t.Fatalf("cancelled check retained proof or failed cleanup: result=%+v cleaned=%t err=%v", result, cleaned, err)
	}
}
