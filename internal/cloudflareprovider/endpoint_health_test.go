package cloudflareprovider

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestEndpointHealthExpiresAndBacksOffFailures(t *testing.T) {
	now := time.Date(2026, 9, 1, 19, 0, 0, 0, time.UTC)
	candidate := scannerCandidate(t)
	first := validScanAttempt(t, candidate, now.Add(-3*time.Second))
	second := validScanAttempt(t, candidate, now.Add(-time.Second))
	report := EvaluateScanReport([]ScanAttempt{first, second}, now, 5*time.Minute)
	health, err := UpdateEndpointHealth(EndpointHealth{}, candidate, report, now)
	if err != nil || !health.Selectable(now) || health.State != EndpointHealthVerified || health.Score != 100 || health.ConsecutiveFailures != 0 || !health.EvidenceValidUntil.Equal(first.FinishedAt.Add(5*time.Minute)) {
		t.Fatalf("verified health=%+v err=%v", health, err)
	}
	if health.Selectable(health.EvidenceValidUntil) {
		t.Fatal("expired endpoint remained selectable")
	}
	failure := second
	failure.Trace, _ = ParseCloudflareTrace([]byte("ip=8.8.8.8\ncolo=DME\nwarp=off\n"))
	failedReport := EvaluateScanReport([]ScanAttempt{first, failure}, now, 5*time.Minute)
	health, err = UpdateEndpointHealth(health, candidate, failedReport, now.Add(time.Second))
	if err != nil || health.Selectable(now.Add(time.Second)) || health.State != EndpointHealthCooldown || health.ConsecutiveFailures != 1 || !health.CooldownUntil.Equal(now.Add(time.Second+time.Minute)) {
		t.Fatalf("first failure health=%+v err=%v", health, err)
	}
	health, _ = UpdateEndpointHealth(health, candidate, failedReport, now.Add(2*time.Second))
	if health.ConsecutiveFailures != 2 || !health.CooldownUntil.Equal(now.Add(2*time.Second+5*time.Minute)) {
		t.Fatal("second cooldown mismatch", health)
	}
	health, _ = UpdateEndpointHealth(health, candidate, failedReport, now.Add(3*time.Second))
	if health.ConsecutiveFailures != 3 || !health.CooldownUntil.Equal(now.Add(3*time.Second+30*time.Minute)) {
		t.Fatal("third cooldown mismatch", health)
	}
	health, err = UpdateEndpointHealth(health, candidate, report, now.Add(4*time.Second))
	if err != nil || !health.Selectable(now.Add(4*time.Second)) || health.ConsecutiveFailures != 0 || !health.CooldownUntil.IsZero() {
		t.Fatalf("verified scan did not reset cooldown: %+v err=%v", health, err)
	}
}

func TestEndpointHealthRejectsForgedOrChangedEvidence(t *testing.T) {
	now := time.Date(2026, 9, 1, 20, 0, 0, 0, time.UTC)
	candidate := scannerCandidate(t)
	report := EvaluateScanReport([]ScanAttempt{validScanAttempt(t, candidate, now.Add(-2*time.Second)), validScanAttempt(t, candidate, now.Add(-time.Second))}, now, time.Minute)
	reportJSON, _ := json.Marshal(report)
	var publicReport ScanReport
	_ = json.Unmarshal(reportJSON, &publicReport)
	if _, err := UpdateEndpointHealth(EndpointHealth{}, candidate, publicReport, now); !errors.Is(err, ErrEndpointHealth) {
		t.Fatal("public report recreated trusted health", err)
	}
	health, err := UpdateEndpointHealth(EndpointHealth{}, candidate, report, now)
	if err != nil {
		t.Fatal(err)
	}
	changed := candidate
	changed.MTU++
	changed.RoutePathID = candidateRoutePathID(changed)
	if _, err := UpdateEndpointHealth(health, changed, report, now); !errors.Is(err, ErrEndpointHealth) {
		t.Fatal("health crossed candidate identity", err)
	}
	healthJSON, _ := json.Marshal(health)
	var publicHealth EndpointHealth
	_ = json.Unmarshal(healthJSON, &publicHealth)
	if publicHealth.Selectable(now) {
		t.Fatal("public health JSON recreated selectable state")
	}
}

func TestCleanupFailureForcesZeroScoreAndCooldown(t *testing.T) {
	now := time.Date(2026, 9, 1, 21, 0, 0, 0, time.UTC)
	candidate := scannerCandidate(t)
	attempt := validScanAttempt(t, candidate, now.Add(-time.Second))
	attempt.CleanupConfirmed = false
	report := EvaluateScanReport([]ScanAttempt{attempt}, now, time.Minute)
	health, err := UpdateEndpointHealth(EndpointHealth{}, candidate, report, now)
	if err != nil || health.Score != 0 || health.State != EndpointHealthCooldown || health.ConsecutiveFailures != 1 {
		t.Fatalf("cleanup failure health=%+v err=%v", health, err)
	}
}
