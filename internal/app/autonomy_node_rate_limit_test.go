package app

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
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
	r.EgressIP, r.Evidence.EgressIP, r.Evidence.Stage = "203.0.113.42", "203.0.113.42", "service"
	return r
}

func nodeRateLimitTelegramService() catalog.Service {
	return catalog.Service{ID: "telegram", Name: "Telegram", Domains: []string{"telegram.org"}, ProbeURL: "https://telegram.org/"}
}

func rateLimitedExactNodeStage(request dataplane.NodeCheckRequest, stage string) dataplane.NodeCheckResult {
	r := rateLimitedExactNode(request)
	if stage == "service_ip" {
		// ExactNodeChecker's existing coercion after domain PASS/IP 429.
		r.Stage, r.Verdict, r.HTTPStatus, r.ErrorCode = "service_ip", evidence.VerdictError, 200, "node-service-ip-path-failed"
		r.Evidence.Verdict = evidence.VerdictError
	}
	return r
}

func failedExactNodeTransport(request dataplane.NodeCheckRequest) dataplane.NodeCheckResult {
	r := autofallbackResult(request, false)
	r.Stage, r.TestLevel, r.ErrorCode, r.DirectControl = "transport", "transport", "node-transport-failed", "not_run"
	r.Evidence = evidence.ProbeEvidence{}
	return r
}

func TestAutonomyExactNode429PreservesCurrentAndResetsOldFailureQuorum(t *testing.T) {
	for _, stage := range []string{"service", "service_ip"} {
		t.Run(stage, func(t *testing.T) {
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
				return rateLimitedExactNodeStage(req, stage), nil
			})
			a.autonomy.mu.Lock()
			r := a.autonomy.doc.Runtime["my-independent-site"]
			r.NextCheck = time.Time{}
			r.Failures = 2
			r.FailureNode = current
			r.Network = committed.NetworkProfileID
			r.FirstFailure = time.Now().Add(-time.Hour)
			r.LastFailure = r.FirstFailure
			spec := a.autonomy.doc.Services["my-independent-site"]
			r.CandidateFailures = []autonomy.CandidateFailure{{NodeID: "node-" + strings.Repeat("e", 64), Network: committed.NetworkProfileID, Definition: spec.Definition, Scope: autonomy.ScopeFingerprint(spec.Sources), PlanID: "dp-1111111111111111", Code: "http-403", ObservedAt: time.Now().Add(-time.Minute), Until: time.Now().Add(time.Minute)}}
			oldCandidateFailures := append([]autonomy.CandidateFailure(nil), r.CandidateFailures...)
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
			if checks != 1 || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(oldSwitches, r.Switches) || !reflect.DeepEqual(oldCandidateFailures, r.CandidateFailures) {
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
		})
	}
}

func TestNodeAutofallbackExact429IsNotDefiniteFailure(t *testing.T) {
	for _, stage := range []string{"service", "service_ip"} {
		t.Run(stage, func(t *testing.T) {
			request := dataplane.NodeCheckRequest{NodeID: "node-a", NetworkProfile: "wan-0123456789ab", Service: nodeRateLimitTelegramService()}
			r := rateLimitedExactNodeStage(request, stage)
			if r.Evidence.HTTPStatus != 429 || r.Evidence.ErrorCode != "http-429" {
				t.Fatal("bad fixture", r)
			}
			if nodeAutofallbackDefiniteFailure(r) || autonomyNodeObservation(r, time.Now()) != "INCONCLUSIVE" {
				t.Fatal("service rate limit became a dead node", r.Verdict, r.ErrorCode)
			}
		})
	}
}

func TestAutonomyExactNode429ColdSearchDoesNotConsumeCandidate(t *testing.T) {
	for _, stage := range []string{"service", "service_ip"} {
		t.Run(stage, func(t *testing.T) {
			a, _, adapter := autonomousIntegrationFixture(t)
			before := a.Store.Get()
			checks := 0
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checks++
				return rateLimitedExactNodeStage(req, stage), nil
			})
			a.autonomyRound(context.Background(), time.Now())
			r := autonomyTestState(a)
			if checks != 1 || r.State != "unconfirmed" || r.Failures != 0 || len(r.Switches) != 0 || len(r.CandidateFailures) != 0 || r.Search == nil || r.Search.Cursor != 0 || r.Search.Halted || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("429 consumed a candidate or Apply", r, checks, adapter.calls)
			}
			a.autonomyRound(context.Background(), time.Now())
			if checks != 1 {
				t.Fatal("429 immediately retried")
			}
		})
	}
}

func TestAutonomyExactNode429ThenRealTransportFailureStillNeedsFreshQuorum(t *testing.T) {
	a, _, adapter := autonomousIntegrationFixture(t)
	phase := "healthy"
	current := ""
	alternates := 0
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		if phase == "429" {
			return rateLimitedExactNode(req), nil
		}
		if phase == "transport" {
			if req.NodeID == current {
				return failedExactNodeTransport(req), nil
			}
			alternates++
		}
		return autofallbackResult(req, true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	if r := autonomyTestState(a); r.State != "applied" {
		t.Fatal(r)
	}
	current = strings.TrimPrefix(selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]), "sing-box:")
	adapter.calls = nil
	phase = "429"
	autonomyTestDue(a, true)
	a.autonomyRound(context.Background(), time.Now())
	if r := autonomyTestState(a); r.Failures != 0 || r.State != "unconfirmed" {
		t.Fatal("429 left an old failure quorum", r)
	}
	phase = "transport"
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Now())
	if r := autonomyTestState(a); r.Failures != 1 || len(adapter.calls) != 0 || alternates != 0 {
		t.Fatal("old quorum authorized immediate handover", r, adapter.calls, alternates)
	}
	autonomyTestDue(a, true)
	a.autonomyRound(context.Background(), time.Now())
	if r := autonomyTestState(a); r.State != "applied" || alternates != 1 || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) == "sing-box:"+current {
		t.Fatal("actual remote transport failure lost failover", r, adapter.calls, alternates)
	}
}

func TestNodeAutofallbackExact429PreservesTelegramGroup(t *testing.T) {
	for _, stage := range []string{"service", "service_ip"} {
		for _, which := range []string{"current", "reserve"} {
			t.Run(stage+"/"+which, func(t *testing.T) {
				a, current, _, adapter, previous := nodeAutofallbackFixture(t, 2)
				profile, err := a.freshNetworkProfile(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				previous.NetworkProfileID = profile
				if err := a.Dataplane.Record(previous); err != nil {
					t.Fatal(err)
				}
				a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
					return autofallbackResult(req, true), nil
				})
				now := time.Now()
				a.nodeAutofallbackRound(context.Background(), now)
				if status := fallbackEntry(t, a); status.State != "healthy" || !status.Healthy {
					t.Fatal("old applied Telegram path was not checked", status)
				}
				before := a.Store.Get()
				adapter.calls = nil
				a.nodeAutofallback.mu.Lock()
				entry := a.nodeAutofallback.entries["telegram"]
				entry.status.Failures = 2
				entry.status.NextCheckAt = time.Time{}
				lastSwitched := entry.lastSwitched
				a.nodeAutofallback.entries["telegram"] = entry
				a.nodeAutofallback.mu.Unlock()
				checks, rateLimited := 0, 0
				a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
					checks++
					if which == "reserve" && req.NodeID == current {
						return failedExactNodeTransport(req), nil
					}
					rateLimited++
					if rateLimited > 1 {
						t.Fatal("429 checker continued to another group member")
					}
					return rateLimitedExactNodeStage(req, stage), nil
				})
				started := time.Now()
				a.nodeAutofallbackRound(context.Background(), started)
				status := fallbackEntry(t, a)
				wantChecks := 1
				if which == "reserve" {
					wantChecks = 2
				}
				if checks != wantChecks || status.State != "unknown" || status.Healthy || status.Failures != 0 || status.NodeID != current || status.CandidateID != "" || !strings.Contains(status.Message, "429") || status.NextCheckAt.Sub(started) < 59*time.Second || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
					t.Fatal("legacy group 429 caused replacement or false health", status, checks, adapter.calls)
				}
				committed, _, err := a.Dataplane.Committed()
				if err != nil || !sameNodeRecoveryPlan(previous, committed) {
					t.Fatal("429 changed complete group plan", err)
				}
				a.nodeAutofallback.mu.Lock()
				after := a.nodeAutofallback.entries["telegram"]
				a.nodeAutofallback.mu.Unlock()
				if !lastSwitched.Equal(after.lastSwitched) || after.cursor != entry.cursor {
					t.Fatal("429 consumed group switch/candidate position")
				}
				a.nodeAutofallbackRound(context.Background(), time.Now())
				if checks != wantChecks {
					t.Fatal("group cooldown retried immediately")
				}
			})
		}
	}
}

func TestExactNode429CannotMaskTLSMisrouteUnknownOrStaleProof(t *testing.T) {
	request := dataplane.NodeCheckRequest{NodeID: "node-a", NetworkProfile: "wan-0123456789ab", Service: nodeRateLimitTelegramService()}
	for _, stage := range []string{"service", "service_ip"} {
		for _, bad := range []string{"tls", "misroute", "leak", "route-proof", "foreign-engine", "foreign-network", "foreign-service", "stale", "stale-evidence", "future", "cleanup", "unavailable-control", "missing-egress", "foreign-egress", "proof-stage", "wrong-status", "wrong-outcome"} {
			t.Run(stage+"/"+bad, func(t *testing.T) {
				r := rateLimitedExactNodeStage(request, stage)
				switch bad {
				case "tls":
					r.Evidence.ErrorCode = "tls-certificate-mismatch"
					r.Verdict = evidence.VerdictError
					if stage == "service" {
						r.ErrorCode = "tls-certificate-mismatch"
					}
				case "misroute":
					r.Verdict = evidence.VerdictMisrouted
					r.Evidence.ObservedRoutePathID = "sing-box:foreign"
				case "leak":
					r.DirectLeak = true
				case "route-proof":
					r.Evidence.RouteProofError = "missing"
				case "foreign-engine":
					r.Evidence.Engine = "xray"
				case "foreign-network":
					r.Evidence.NetworkProfile = "wan-ffffffffffff"
				case "foreign-service":
					r.Evidence.Service = "other"
				case "stale":
					r.ExpiresAt = time.Now().Add(-time.Second)
				case "stale-evidence":
					r.Evidence.StartedAt = r.StartedAt.Add(-time.Hour)
					r.Evidence.FinishedAt = r.StartedAt.Add(-time.Minute)
				case "future":
					r.FinishedAt = time.Now().Add(time.Hour)
				case "cleanup":
					r.Stage = "cleanup"
					r.ErrorCode = "node-cleanup-failed"
				case "unavailable-control":
					r.DirectControl = "unavailable"
				case "missing-egress":
					r.EgressIP = ""
				case "foreign-egress":
					r.Evidence.EgressIP = "203.0.113.99"
				case "proof-stage":
					r.Evidence.Stage = "egress"
				case "wrong-status":
					r.Evidence.HTTPStatus = 503
				case "wrong-outcome":
					r.Evidence.Outcome = evidence.OutcomeUnknown
				}
				if nodeServiceRateLimitSeconds(r, time.Now()) != 0 || autonomyNodeObservation(r, time.Now()) == "PASS" {
					t.Fatal("invalid 429 got pause or positive proof", r)
				}
				if (bad == "tls" || bad == "misroute") && !nodeAutofallbackDefiniteFailure(r) {
					t.Fatal("ordinary failure semantics weakened", bad)
				}
			})
		}
	}
	transport := failedExactNodeTransport(request)
	if !nodeAutofallbackDefiniteFailure(transport) || autonomyNodeObservation(transport, time.Now()) != "FAIL" {
		t.Fatal("remote timeout/transport failure no longer counts")
	}
}

func TestAutonomyExactNode429ReserveDoesNotConsumeOrApplyOldReady(t *testing.T) {
	a, _, adapter := autonomousIntegrationFixture(t)
	snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174002@third.example:443?security=tls", time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, n := range snapshot.Nodes {
		ids = append(ids, n.ID)
	}
	slices.Sort(ids)
	d10Options(a, ids)
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.CandidatesPerRound = 1
	a.autonomy.doc.Policy.Revision++
	if err := a.persistAutonomyLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.autonomy.mu.Unlock()
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return autofallbackResult(req, true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	if r := autonomyTestState(a); r.State != "applied" {
		t.Fatal(r)
	}
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Now())
	r := autonomyTestState(a)
	if r.State != "healthy" || len(r.Reserves) != 2 {
		t.Fatal("healthy primary/reserve baseline absent", r)
	}
	before := a.Store.Get()
	current := strings.TrimPrefix(selectedRoute(before.AppliedServices["my-independent-site"]), "sing-box:")
	reserve := r.Reserves[0]
	if reserve == current {
		reserve = r.Reserves[1]
	}
	cursor := slices.Index(ids, reserve)
	if cursor < 0 {
		t.Fatal("reserve absent")
	}
	a.autonomy.mu.Lock()
	r.NextCheck = time.Time{}
	r.ReserveCheckedAt = time.Now().Add(-time.Hour)
	r.Cursor = cursor
	a.autonomy.doc.Runtime["my-independent-site"] = r
	if err := a.persistAutonomyLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.autonomy.mu.Unlock()
	budget := append([]time.Time(nil), r.Switches...)
	adapter.calls = nil
	checks := []string{}
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checks = append(checks, req.NodeID)
		if req.NodeID == current {
			return autofallbackResult(req, true), nil
		}
		if req.NodeID != reserve {
			t.Fatal("reserve 429 continued to another candidate")
		}
		return rateLimitedExactNode(req), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	r = autonomyTestState(a)
	if r.State != "unconfirmed" || r.Cursor != cursor || !reflect.DeepEqual(checks, []string{current, reserve}) || !reflect.DeepEqual(adapter.calls, []string{"health"}) || !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(r.Switches, budget) || len(r.CandidateFailures) != 0 {
		t.Fatal("reserve 429 consumed cursor/Apply or stale ready", r, checks, adapter.calls)
	}
	profile, err := a.freshNetworkProfile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Nodes.ResolveRouteForEngine(context.Background(), "sing-box", reserve, "my-independent-site", profile, "", time.Time{}, time.Now()); err == nil {
		t.Fatal("429 renewed the reserve's prior PASS")
	}
}
