package app

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/probecheck"
)

// Actual HTTP verdict evaluator and exact-result shape; protocol/OS work in
// the coordinator fixtures remains modeled. No native availability is implied.
func rateLimitedExactNode(request dataplane.NodeCheckRequest) dataplane.NodeCheckResult {
	r := autofallbackResult(request, false)
	p := request.Service.Probes
	probe := request.Service.ProbeURL
	if len(p) > 0 {
		probe = p[0].URL
	}
	assessment := probecheck.Evaluate(request.Service, catalog.Probe{ID: "web", URL: probe, Required: true}, probecheck.Observation{RequestedURL: probe, FinalURL: probe, HTTPStatus: 429, ExpectedRoutePathID: r.RoutePathID, ObservedRoutePathID: r.RoutePathID})
	r.HTTPStatus, r.Verdict, r.ErrorCode = 429, assessment.Verdict, assessment.ErrorCode
	r.Evidence.HTTPStatus, r.Evidence.Verdict, r.Evidence.Outcome, r.Evidence.ErrorCode = 429, assessment.Verdict, assessment.Outcome, assessment.ErrorCode
	return r
}

func nodeRateLimitTelegramService() catalog.Service {
	return catalog.Service{ID: "telegram", Name: "Telegram", Domains: []string{"telegram.org"}, ProbeURL: "https://telegram.org/"}
}

func TestAutonomyExactNode429PreservesCurrentAndResetsOldFailureQuorum(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return autofallbackResult(req, true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	if r := autonomyTestState(a); r.State != "applied" {
		t.Fatal("baseline not committed", r)
	}
	before := a.Store.Get()
	committed, _, err := a.Dataplane.Committed()
	if err != nil {
		t.Fatal(err)
	}
	current := strings.TrimPrefix(selectedRoute(before.AppliedServices["my-independent-site"]), "sing-box:")
	adapter.calls = nil
	checks := 0
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checks++
		if req.NodeID != current {
			t.Fatal("rate limit reached an alternate node", ids, req.NodeID)
		}
		return rateLimitedExactNode(req), nil
	})
	a.autonomy.mu.Lock()
	r := a.autonomy.doc.Runtime["my-independent-site"]
	r.NextCheck = time.Time{}
	r.Failures = 2
	r.FailureNode = current
	r.Network = committed.NetworkProfileID
	r.FirstFailure = time.Now().Add(-time.Hour)
	r.LastFailure = r.FirstFailure
	oldSwitches := append([]time.Time(nil), r.Switches...)
	a.autonomy.doc.Runtime["my-independent-site"] = r
	if err := a.persistAutonomyLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.autonomy.mu.Unlock()
	start := time.Now()
	a.autonomyRound(context.Background(), start)
	r = autonomyTestState(a)
	if r.State != "unconfirmed" || r.Failures != 0 || !r.FirstFailure.IsZero() || !r.LastFailure.IsZero() || !strings.Contains(r.Message, "429") || r.NextCheck.Sub(start) < 59*time.Second || r.NextCheck.Sub(start) > 65*time.Second {
		t.Fatal("exact-node rate limit did not defer this service", r)
	}
	if checks != 1 || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(oldSwitches, r.Switches) {
		t.Fatal("429 mutated live runtime/config or consumed Apply", checks, adapter.calls, r.Switches)
	}
	after, _, err := a.Dataplane.Committed()
	if err != nil || !reflect.DeepEqual(committed, after) {
		t.Fatal("429 replaced the complete committed plan", err)
	}
	a.autonomyRound(context.Background(), time.Now())
	if checks != 1 {
		t.Fatal("cooldown retried the checker")
	}
}

func TestNodeAutofallbackExact429IsNotDefiniteFailure(t *testing.T) {
	request := dataplane.NodeCheckRequest{NodeID: "node-a", NetworkProfile: "wan-0123456789ab", Service: nodeRateLimitTelegramService()}
	r := rateLimitedExactNode(request)
	if r.Verdict != evidence.VerdictPartial || r.ErrorCode != "http-429" {
		t.Fatal("bad fixture", r)
	}
	if nodeAutofallbackDefiniteFailure(r) || autonomyNodeObservation(r, time.Now()) != "INCONCLUSIVE" {
		t.Fatal("service rate limit became a dead node", r.Verdict, r.ErrorCode)
	}
}
