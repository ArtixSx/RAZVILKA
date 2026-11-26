package dataplane

import (
	"context"
	"testing"
	"time"
)

func TestExactNodeTimingIncludesValidationAndCleanupWithoutRenewingEvidence(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	started := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	now := started
	checker.now = func() time.Time { return now }
	checker.runtimeReady = func() bool {
		now = started.Add(2 * time.Second)
		return true
	}
	checks := 0
	checker.FreshProfile = func(context.Context) (string, error) {
		checks++
		if checks == 1 {
			now = started.Add(5 * time.Second)
		}
		return "wan-0123456789ab", nil
	}
	prepare := checker.prepare
	checker.prepare = func(ctx context.Context, session exactNodeSession, request NodeCheckRequest, endpoint exactNodeEndpoint) (exactNodeSession, error) {
		now = started.Add(6 * time.Second)
		return prepare(ctx, session, request, endpoint)
	}
	checker.cleanup = func(context.Context, exactNodeSession) error {
		now = started.Add(10 * time.Second)
		return nil
	}
	result, err := checker.Check(context.Background(), checkedNodeRequest())
	if err != nil || !result.Available || result.CleanupStatus != NodeCleanupVerified {
		t.Fatalf("successful check changed: %+v %v", result, err)
	}
	if !result.StartedAt.Equal(started) || !result.FinishedAt.Equal(now) || result.LatencyMS != 10000 {
		t.Fatalf("reported duration omitted validation or cleanup: start=%s finish=%s duration=%d", result.StartedAt, result.FinishedAt, result.LatencyMS)
	}
	if !result.ExpiresAt.Equal(started.Add(6*time.Second + checker.evidenceTTL())) {
		t.Fatalf("cleanup extended evidence freshness: %s", result.ExpiresAt)
	}
	for _, stage := range result.Stages {
		if stage.ID == "cleanup" {
			if stage.Status != "passed" || stage.Duration != 4000 {
				t.Fatalf("cleanup timing is not its measured duration: %+v", stage)
			}
			return
		}
	}
	t.Fatal("successful cleanup is missing from stage diagnostics")
}
