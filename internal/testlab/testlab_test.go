package testlab

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/probecheck"
)

func TestProbeCurrent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer ts.Close()
	r := NewRunner()
	r.Client = ts.Client()
	r.Client.Timeout = 2 * time.Second
	cat := catalog.Catalog{Services: []catalog.Service{{ID: "test", Name: "Test", ProbeURL: ts.URL}}}
	got := r.ProbeCurrent(context.Background(), cat, nil)
	if len(got) != 1 || got[0].Status != "pass" || got[0].HTTPStatus != 204 {
		t.Fatalf("unexpected result: %+v", got)
	}
	if got[0].EvidenceLevel != evidence.Runtime {
		t.Fatalf("current route must only prove runtime reachability: %+v", got[0])
	}
	snap := r.Snapshot(cat)
	if len(snap.Current) != 1 {
		t.Fatalf("snapshot missing result: %+v", snap)
	}
}

func TestProbeCurrentDetectsInterruptedResponseStream(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "32768")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", 16384)))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		time.Sleep(180 * time.Millisecond)
	}))
	defer ts.Close()
	runner := NewRunner()
	runner.Client = ts.Client()
	runner.Client.Timeout = 60 * time.Millisecond
	cat := catalog.Catalog{Services: []catalog.Service{{ID: "stream", Name: "Stream", ProbeURL: ts.URL}}}
	got := runner.ProbeCurrent(context.Background(), cat, nil)
	if len(got) != 1 || got[0].Status != "fail" || got[0].StreamStatus != "interrupted" || got[0].BytesRead == 0 {
		t.Fatalf("interrupted stream was not detected: %+v", got)
	}
}

func TestDecodeRunRequest(t *testing.T) {
	ids, err := DecodeRunRequest(strings.NewReader(`{"services":["youtube","chatgpt"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "youtube" {
		t.Fatalf("ids=%v", ids)
	}
}

type fakeRouteProber struct{}

func (fakeRouteProber) Probe(_ context.Context, service catalog.Service, route string) Result {
	return Result{ServiceID: service.ID, ServiceName: service.Name, Route: route, Status: "pass", HTTPStatus: 204, RouteConfirmed: true, EvidenceSource: "test", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
}

type scenarioRouteProber struct{}

func (scenarioRouteProber) Probe(_ context.Context, service catalog.Service, route string) Result {
	status := "pass"
	if strings.Contains(service.ProbeURL, "web.example") {
		status = "fail"
	}
	return Result{ServiceID: service.ID, ServiceName: service.Name, ProbeURL: service.ProbeURL, Route: route, Status: status, HTTPStatus: 204, RouteConfirmed: true, EvidenceSource: "scenario-test", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
}

func TestProbeRoutesStoresConfirmedMatrixEvidence(t *testing.T) {
	runner := NewRunner()
	cat := catalog.Catalog{Services: []catalog.Service{{ID: "video", Name: "Video", ProbeURL: "https://example.com/"}}}
	results := runner.ProbeRoutes(context.Background(), cat, []string{"video"}, []string{"warp-wg"}, fakeRouteProber{})
	if len(results) != 1 || !results[0].RouteConfirmed || results[0].EvidenceLevel != evidence.Service {
		t.Fatalf("results = %+v", results)
	}
	snapshot := runner.Snapshot(cat)
	found := false
	for _, cell := range snapshot.Matrix {
		if cell.ServiceID == "video" && cell.Route == "warp-wg" && cell.Last != nil {
			found = cell.Status == "pass" && cell.Last.RouteConfirmed
		}
	}
	if !found {
		t.Fatalf("confirmed matrix cell missing: %+v", snapshot.Matrix)
	}
}

func TestPolicyHTTPResponseNeverBecomesServiceConfirmed(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusUnavailableForLegalReasons} {
		result := Result{ServiceID: "telegram", Route: "warp-wg", Status: "partial", HTTPStatus: status, RouteConfirmed: true, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
		result.NormalizeEvidence()
		if result.EvidenceLevel != evidence.Route || result.Outcome != evidence.OutcomeServiceBlocked || result.EvidenceV2 == nil || result.EvidenceFreshUntil == "" {
			t.Fatalf("HTTP %d produced unsafe evidence: %+v", status, result)
		}
	}
}

func TestTLSMismatchNeverBecomesServiceConfirmed(t *testing.T) {
	result := Result{ServiceID: "telegram", Route: "warp-wg", Status: "fail", RouteConfirmed: true, Detail: "tls: certificate is valid for another.example", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	result.NormalizeEvidence()
	if result.EvidenceLevel != evidence.Route || result.Outcome != evidence.OutcomeContentMismatch || result.EvidenceV2.ErrorCode != "tls-certificate-mismatch" {
		t.Fatalf("TLS mismatch produced unsafe evidence: %+v", result)
	}
}

func TestRequiredScenarioFailureCannotBeHiddenByLandingPage(t *testing.T) {
	runner := NewRunner()
	cat := catalog.Catalog{Services: []catalog.Service{{
		ID: "telegram", Name: "Telegram", ProbeURL: "https://telegram.example/",
		Probes: []catalog.Probe{
			{ID: "site", Label: "Сайт", URL: "https://telegram.example/", Required: true},
			{ID: "web", Label: "Web-клиент", URL: "https://web.example/", Required: true},
		},
	}}}
	results := runner.ProbeRoutes(context.Background(), cat, []string{"telegram"}, []string{"warp-wg"}, scenarioRouteProber{})
	if len(results) != 2 || results[0].ScenarioID == "" || results[1].ScenarioID == "" {
		t.Fatalf("scenario results = %+v", results)
	}
	aggregated := AggregateScenarios(results)
	if len(aggregated) != 1 || aggregated[0].Status != "fail" || !strings.Contains(aggregated[0].Detail, "Web-клиент") {
		t.Fatalf("aggregate = %+v", aggregated)
	}
	assessment := AssessComparisons(append(results, Result{ServiceID: "telegram", ServiceName: "Telegram", Route: "direct", Status: "fail", RouteConfirmed: true}))
	if len(assessment) != 1 || assessment[0].Conclusion != "no-working-route" {
		t.Fatalf("assessment must reject partially working bypass: %+v", assessment)
	}
}

func TestAggregateCannotHideBlockedRequiredScenario(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	rows := []Result{
		{ServiceID: "telegram", Route: "warp-wg", ScenarioID: "site", ScenarioLabel: "Сайт", ScenarioNeeded: true, Status: "pass", HTTPStatus: 200, RouteConfirmed: true, CheckedAt: now},
		{ServiceID: "telegram", Route: "warp-wg", ScenarioID: "web", ScenarioLabel: "Web", ScenarioNeeded: true, Status: "partial", HTTPStatus: 451, RouteConfirmed: true, CheckedAt: now},
	}
	for index := range rows {
		rows[index].NormalizeEvidence()
	}
	aggregated := AggregateScenarios(rows)
	if len(aggregated) != 1 || aggregated[0].AssuranceLevel() != evidence.Route || aggregated[0].Outcome != evidence.OutcomeServiceBlocked {
		t.Fatalf("blocked required scenario was promoted: %+v", aggregated)
	}
}

func TestAssessComparisonsRequiresBypassAfterFailedDirectControl(t *testing.T) {
	results := []Result{
		{ServiceID: "telegram", ServiceName: "Telegram", Route: "direct", Status: "fail", RouteConfirmed: true},
		{ServiceID: "telegram", ServiceName: "Telegram", Route: "nfqws2", Status: "pass", HTTPStatus: 204, RouteConfirmed: true, LatencyMS: 20},
	}
	got := AssessComparisons(results)
	if len(got) != 1 || got[0].Conclusion != "bypass-required" || got[0].RecommendedRoute != "nfqws2" || got[0].BypassRequired == nil || !*got[0].BypassRequired {
		t.Fatalf("assessment = %+v", got)
	}
}

func TestAssessComparisonsPrefersWorkingDirectControl(t *testing.T) {
	results := []Result{
		{ServiceID: "telegram", ServiceName: "Telegram", Route: "direct", Status: "pass", HTTPStatus: 204, RouteConfirmed: true, LatencyMS: 40},
		{ServiceID: "telegram", ServiceName: "Telegram", Route: "warp-wg", Status: "pass", HTTPStatus: 204, RouteConfirmed: true, LatencyMS: 15},
	}
	got := AssessComparisons(results)
	if len(got) != 1 || got[0].Conclusion != "direct-sufficient" || got[0].RecommendedRoute != "direct" || got[0].BypassRequired == nil || *got[0].BypassRequired {
		t.Fatalf("assessment = %+v", got)
	}
}

func TestAssessComparisonsDoesNotInventUnavailableDirectControl(t *testing.T) {
	results := []Result{
		{ServiceID: "telegram", ServiceName: "Telegram", Route: "direct", Status: "not-ready", Detail: "external tunnel present"},
		{ServiceID: "telegram", ServiceName: "Telegram", Route: "warp-wg", Status: "pass", HTTPStatus: 204, RouteConfirmed: true},
	}
	got := AssessComparisons(results)
	if len(got) != 1 || got[0].Conclusion != "control-unavailable" || got[0].RecommendedRoute != "warp-wg" || got[0].BypassRequired != nil {
		t.Fatalf("assessment = %+v", got)
	}
}

func TestDeclaredPassWithoutHTTPIsInconclusive(t *testing.T) {
	result := Result{Route: "sing-box", Status: "pass", RouteConfirmed: true}
	result.NormalizeEvidence()
	if result.Verdict != evidence.VerdictInconclusive || result.AssuranceLevel().AtLeast(evidence.Service) {
		t.Fatalf("listener-only success became service proof: %+v", result)
	}
}

func TestDirectLeakCannotBecomeServiceProof(t *testing.T) {
	result := Result{Route: "sing-box", Status: "pass", HTTPStatus: 200, RouteConfirmed: true}
	result.EvaluateHTTP(catalog.Service{}, probecheck.Observation{HTTPStatus: 200, ExpectedRoutePathID: "isolated:sing-box", ObservedRoutePathID: "isolated:direct"})
	result.NormalizeEvidence()
	if result.Verdict != evidence.VerdictMisrouted || result.RouteConfirmed || result.AssuranceLevel() != evidence.Runtime {
		t.Fatalf("direct leak was promoted: %+v", result)
	}
}

func TestAggregateKeepsBlockedVerdictAfterSuccessfulFirstScenario(t *testing.T) {
	rows := []Result{
		{ServiceID: "telegram", Route: "warp-wg", ScenarioID: "site", ScenarioNeeded: true, Status: "pass", HTTPStatus: 200, RouteConfirmed: true, Verdict: evidence.VerdictPass, Outcome: evidence.OutcomeServiceAccepted},
		{ServiceID: "telegram", Route: "warp-wg", ScenarioID: "web", ScenarioNeeded: true, Status: "partial", HTTPStatus: 200, RouteConfirmed: true, Verdict: evidence.VerdictBlocked, Outcome: evidence.OutcomeServiceBlocked, ErrorCode: "known-block-page"},
	}
	got := AggregateScenarios(rows)
	if len(got) != 1 || got[0].Verdict != evidence.VerdictBlocked || got[0].Outcome != evidence.OutcomeServiceBlocked || got[0].AssuranceLevel() != evidence.Route {
		t.Fatalf("aggregate hid block page: %+v", got)
	}
}
