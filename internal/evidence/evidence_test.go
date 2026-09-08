package evidence

import (
	"testing"
	"time"
)

func TestFromProbeDoesNotPromoteCurrentPath(t *testing.T) {
	if got := FromProbe("pass", false); got != Runtime {
		t.Fatalf("current-path pass = %q, want %q", got, Runtime)
	}
	if Runtime.AtLeast(Service) {
		t.Fatal("runtime reachability was treated as service-route evidence")
	}
}

func TestFromProbeRequiresRouteAndServiceSuccess(t *testing.T) {
	if got := FromProbe("pass", true); got != Route {
		t.Fatalf("legacy status without HTTP facts became %s", got)
	}
	if got := FromProbe("fail", true); got != Route {
		t.Fatalf("confirmed failed route = %q, want %q", got, Route)
	}
	if got := FromProbe("partial", true); got != Route {
		t.Fatalf("confirmed partial response = %q, want %q", got, Route)
	}
	if !Service.AtLeast(Route) || Route.AtLeast(Service) {
		t.Fatal("assurance ordering is invalid")
	}
}

func TestEvidenceV2NeverPromotesBlockedOrMismatchedContent(t *testing.T) {
	now := time.Now().UTC()
	for _, outcome := range []Outcome{OutcomeServiceBlocked, OutcomeContentMismatch, OutcomeEdgeUnsuitable, OutcomeTransportReachable} {
		probe := ProbeEvidence{SchemaVersion: ProbeSchemaVersion, StartedAt: now.Add(-time.Second), FinishedAt: now, RoutePathID: "isolated:warp", Outcome: outcome}
		if got := probe.AssuranceLevel(); got != Route {
			t.Fatalf("outcome %s = %s, want route-confirmed", outcome, got)
		}
	}
	accepted := ProbeEvidence{SchemaVersion: ProbeSchemaVersion, StartedAt: now.Add(-time.Second), FinishedAt: now, RoutePathID: "isolated:warp", Outcome: OutcomeServiceAccepted, HTTPStatus: 204}
	if got := accepted.AssuranceLevel(); got != Service {
		t.Fatalf("accepted service = %s", got)
	}
}

func TestEvidenceV2FreshnessAndCurrentPath(t *testing.T) {
	now := time.Now().UTC()
	probe := ProbeEvidence{SchemaVersion: ProbeSchemaVersion, StartedAt: now.Add(-time.Minute), FinishedAt: now, Outcome: OutcomeServiceAccepted}
	if got := probe.AssuranceLevel(); got != Runtime {
		t.Fatalf("current-path accepted response = %s", got)
	}
	if !probe.Fresh(now, 24*time.Hour) || probe.Fresh(now.Add(25*time.Hour), 24*time.Hour) {
		t.Fatal("freshness window is incorrect")
	}
}

func TestOutcomeFromProbeClassifiesPolicyResponses(t *testing.T) {
	for status, want := range map[int]Outcome{204: OutcomeServiceAccepted, 403: OutcomeServiceBlocked, 451: OutcomeServiceBlocked, 429: OutcomeEdgeUnsuitable, 404: OutcomeTransportReachable} {
		probeStatus := "partial"
		if status == 204 {
			probeStatus = "pass"
		}
		if got := OutcomeFromProbe(probeStatus, status, ""); got != want {
			t.Fatalf("HTTP %d = %s, want %s", status, got, want)
		}
	}
	if got := OutcomeFromProbe("fail", 0, "tls-certificate-mismatch"); got != OutcomeContentMismatch {
		t.Fatalf("TLS mismatch = %s", got)
	}
}

func TestNotReadyHasNoEvidence(t *testing.T) {
	if got := FromProbe("not-ready", true); got != None {
		t.Fatalf("not-ready = %q, want %q", got, None)
	}
}

func TestStrongerIgnoresInvalidLevel(t *testing.T) {
	if got := Stronger(Level("invented"), Route); got != Route {
		t.Fatalf("stronger level = %q, want %q", got, Route)
	}
}

func TestWeakerKeepsAggregateAtLeastProvenRoute(t *testing.T) {
	if got := Weaker(Service, None); got != None {
		t.Fatalf("weaker level = %q, want %q", got, None)
	}
	if got := Weaker(Service, Route); got != Route {
		t.Fatalf("weaker level = %q, want %q", got, Route)
	}
}
