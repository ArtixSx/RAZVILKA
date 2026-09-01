package cloudflareprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/evidence"
)

func scannerCandidate(t *testing.T) CandidatePreview {
	t.Helper()
	store, account, _ := storedCandidate(t, 31)
	var preview CandidatePreview
	if err := store.WithWireGuardCandidate(context.Background(), account.ID, CandidateOptions{}, func(_ context.Context, candidate WireGuardCandidate) error {
		preview = candidate.Public()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return preview
}

func validScanAttempt(t *testing.T, candidate CandidatePreview, finished time.Time) ScanAttempt {
	t.Helper()
	trace, err := ParseCloudflareTrace([]byte("fl=1\nip=8.8.8.8\ncolo=DME\nwarp=on\n"))
	if err != nil {
		t.Fatal(err)
	}
	started := finished.Add(-2 * time.Second)
	return ScanAttempt{
		Candidate: candidate, StartedAt: started, FinishedAt: finished, Reachable: true,
		HandshakeAt: started.Add(time.Second), EgressIP: "8.8.8.8", DirectEgressIP: "9.9.9.9", Trace: trace,
		ServiceID: "telegram",
		Service: evidence.ProbeEvidence{
			SchemaVersion: evidence.ProbeSchemaVersion, StartedAt: started, FinishedAt: finished,
			Service: "telegram", EgressIP: "8.8.8.8",
			RoutePathID: candidate.RoutePathID, ExpectedRoutePathID: candidate.RoutePathID, ObservedRoutePathID: candidate.RoutePathID,
			Outcome: evidence.OutcomeServiceAccepted, Verdict: evidence.VerdictPass, HTTPStatus: 200,
		},
		ConfirmedMTU: candidate.MTU, CleanupConfirmed: true,
	}
}

func TestCloudflareTraceParserIsStrict(t *testing.T) {
	valid, err := ParseCloudflareTrace([]byte("ip=8.8.8.8\ncolo=DME\nwarp=on\nfuture=value\n"))
	if err != nil || !valid.valid || valid.WARP != "on" {
		t.Fatal(valid, err)
	}
	for _, input := range [][]byte{
		nil,
		[]byte("<html>portal</html>"),
		[]byte("ip=8.8.8.8\nip=1.1.1.1\ncolo=DME\nwarp=on\n"),
		[]byte("ip=192.168.1.1\ncolo=DME\nwarp=on\n"),
		[]byte("ip=203.0.113.9\ncolo=DME\nwarp=on\n"),
		[]byte("ip=8.8.8.8\ncolo=dme\nwarp=on\n"),
		[]byte("ip=8.8.8.8\ncolo=DME\nwarp=maybe\n"),
		bytes.Repeat([]byte{'x'}, MaxTraceBytes+1),
	} {
		if _, err := ParseCloudflareTrace(input); err == nil {
			t.Fatalf("invalid trace accepted: %.80q", input)
		}
	}
}

func TestScanAttemptRejectsEveryPartialProof(t *testing.T) {
	now := time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	candidate := scannerCandidate(t)
	base := validScanAttempt(t, candidate, now.Add(-time.Second))
	offTrace, _ := ParseCloudflareTrace([]byte("ip=8.8.8.8\ncolo=DME\nwarp=off\n"))
	wrongTrace, _ := ParseCloudflareTrace([]byte("ip=1.1.1.1\ncolo=DME\nwarp=on\n"))
	cases := map[string]func(*ScanAttempt){
		"reachability-only": func(value *ScanAttempt) { value.HandshakeAt = time.Time{} },
		"direct-leak":       func(value *ScanAttempt) { value.DirectEgressIP = value.EgressIP },
		"warp-off":          func(value *ScanAttempt) { value.Trace = offTrace },
		"trace-ip-mismatch": func(value *ScanAttempt) { value.Trace = wrongTrace },
		"generic-http":      func(value *ScanAttempt) { value.Service.RoutePathID = "" },
		"wrong-route":       func(value *ScanAttempt) { value.Service.ObservedRoutePathID = "direct" },
		"wrong-service":     func(value *ScanAttempt) { value.Service.Service = "youtube" },
		"wrong-service-ip":  func(value *ScanAttempt) { value.Service.EgressIP = "1.1.1.1" },
		"outside-window":    func(value *ScanAttempt) { value.Service.StartedAt = value.StartedAt.Add(-time.Second) },
		"redirect": func(value *ScanAttempt) {
			value.Service.Outcome, value.Service.Verdict, value.Service.HTTPStatus = evidence.OutcomeTransportReachable, evidence.VerdictInconclusive, 302
		},
		"mtu":     func(value *ScanAttempt) { value.ConfirmedMTU-- },
		"cleanup": func(value *ScanAttempt) { value.CleanupConfirmed = false },
		"stale":   func(value *ScanAttempt) { value.FinishedAt = now.Add(-10 * time.Minute) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			attempt := base
			mutate(&attempt)
			if result := EvaluateScanAttempt(attempt, now, time.Minute); result.Verified || result.ReasonCode == "verified" {
				t.Fatalf("partial evidence was promoted: %+v", result)
			}
		})
	}
}

func TestSerializedPublicEvidenceCannotRecreateProof(t *testing.T) {
	now := time.Date(2026, 9, 1, 15, 30, 0, 0, time.UTC)
	attempt := validScanAttempt(t, scannerCandidate(t), now.Add(-time.Second))
	candidateJSON, _ := json.Marshal(attempt.Candidate)
	traceJSON, _ := json.Marshal(attempt.Trace)
	var publicCandidate CandidatePreview
	var publicTrace TraceEvidence
	if json.Unmarshal(candidateJSON, &publicCandidate) != nil || json.Unmarshal(traceJSON, &publicTrace) != nil {
		t.Fatal("public evidence did not round-trip")
	}
	attempt.Candidate = publicCandidate
	attempt.Trace = publicTrace
	if result := EvaluateScanAttempt(attempt, now, time.Minute); result.Verified || result.ReasonCode != "candidate-identity-invalid" {
		t.Fatalf("serialized public view recreated internal proof: %+v", result)
	}
}

func TestScanReportRequiresTwoExactAttemptsAndCleanup(t *testing.T) {
	now := time.Date(2026, 9, 1, 16, 0, 0, 0, time.UTC)
	candidate := scannerCandidate(t)
	first := validScanAttempt(t, candidate, now.Add(-3*time.Second))
	second := validScanAttempt(t, candidate, now.Add(-time.Second))
	report := EvaluateScanReport([]ScanAttempt{first, second}, now, 5*time.Minute)
	if !report.Verified || report.Passes != 2 || report.Score != 100 || report.ReasonCode != "verified" || len(report.Results) != 2 || !report.ValidUntil.Equal(first.FinishedAt.Add(5*time.Minute)) {
		t.Fatalf("valid repeated scan was not verified: %+v", report)
	}
	third := second
	third.CleanupConfirmed = false
	report = EvaluateScanReport([]ScanAttempt{first, second, third}, now, 5*time.Minute)
	if report.Verified || report.ReasonCode != "cleanup-unconfirmed" {
		t.Fatalf("cleanup failure was ignored: %+v", report)
	}
	other := second
	other.Candidate.RoutePathID = strings.Replace(other.Candidate.RoutePathID, "cloudflare-wg:", "cloudflare-wg:x", 1)
	report = EvaluateScanReport([]ScanAttempt{first, other}, now, 5*time.Minute)
	if report.Verified || report.ReasonCode != "candidate-identity-changed" {
		t.Fatalf("candidate identity change was ignored: %+v", report)
	}
}
