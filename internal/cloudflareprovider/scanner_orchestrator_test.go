package cloudflareprovider

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type mockScanRunner struct {
	t             *testing.T
	now           time.Time
	candidateSeen []CandidatePreview
	requests      []ScanRunRequest
	cleanup       bool
	errAt         int
	block         bool
}

func (runner *mockScanRunner) RunScanAttempt(ctx context.Context, candidate WireGuardCandidate, request ScanRunRequest) (ScanAttempt, error) {
	runner.requests = append(runner.requests, request)
	runner.candidateSeen = append(runner.candidateSeen, candidate.Public())
	if runner.block {
		<-ctx.Done()
		return ScanAttempt{}, ctx.Err()
	}
	attempt := validScanAttempt(runner.t, candidate.Public(), runner.now.Add(time.Duration(request.Attempt)*time.Second))
	attempt.Candidate = CandidatePreview{RoutePathID: "runner-must-not-control-this"}
	attempt.ServiceID = "runner-must-not-control-this"
	attempt.CleanupConfirmed = runner.cleanup
	if runner.errAt == request.Attempt {
		return attempt, errors.New("private runner detail")
	}
	return attempt, nil
}

func TestScannerRunsBoundedRepeatedAttemptsAndOwnsIdentity(t *testing.T) {
	now := time.Date(2026, 9, 1, 17, 0, 0, 0, time.UTC)
	store, account, _ := storedCandidate(t, 37)
	runner := &mockScanRunner{t: t, now: now.Add(-5 * time.Second), cleanup: true}
	waits := []time.Duration{}
	scanner := Scanner{
		Runner: runner, Random: bytes.NewReader(bytes.Repeat([]byte{1}, 64)), Now: func() time.Time { return now },
		Wait: func(_ context.Context, delay time.Duration) error { waits = append(waits, delay); return nil },
	}
	report, err := scanner.Scan(context.Background(), store, account.ID, ScanOptions{ServiceID: "telegram", Attempts: 3, EvidenceTTL: time.Minute, AttemptTimeout: time.Second, MaxJitter: time.Second})
	if err != nil || !report.Verified || report.Passes != 3 || len(runner.requests) != 3 || len(waits) != 2 {
		t.Fatalf("scan report=%+v requests=%v waits=%v err=%v", report, runner.requests, waits, err)
	}
	for index, request := range runner.requests {
		if request.Attempt != index+1 || request.ServiceID != "telegram" || runner.candidateSeen[index].RoutePathID != report.RoutePathID {
			t.Fatal("scanner did not bind attempt identity", request, runner.candidateSeen[index])
		}
	}
}

func TestScannerStopsAfterCleanupFailure(t *testing.T) {
	now := time.Date(2026, 9, 1, 17, 30, 0, 0, time.UTC)
	store, account, _ := storedCandidate(t, 41)
	runner := &mockScanRunner{t: t, now: now.Add(-5 * time.Second), cleanup: false}
	scanner := Scanner{Runner: runner, Now: func() time.Time { return now }}
	report, err := scanner.Scan(context.Background(), store, account.ID, ScanOptions{ServiceID: "telegram"})
	if err != nil || report.Verified || report.ReasonCode != "cleanup-unconfirmed" || len(runner.requests) != 1 {
		t.Fatalf("unsafe cleanup did not stop scan: report=%+v calls=%d err=%v", report, len(runner.requests), err)
	}
}

func TestScannerScanAndRecordCommitsSelectableHealth(t *testing.T) {
	now := time.Date(2026, 9, 1, 17, 45, 0, 0, time.UTC)
	store, account, _ := storedCandidate(t, 42)
	runner := &mockScanRunner{t: t, now: now.Add(-5 * time.Second), cleanup: true}
	scanner := Scanner{Runner: runner, Now: func() time.Time { return now }, Wait: func(context.Context, time.Duration) error { return nil }}
	report, health, err := scanner.ScanAndRecord(context.Background(), store, account.ID, ScanOptions{ServiceID: "telegram", EvidenceTTL: time.Minute})
	if err != nil || !report.Verified || !health.Selectable(now) || health.RoutePathID != report.RoutePathID {
		t.Fatalf("scan report=%+v health=%+v err=%v", report, health, err)
	}
	loaded, exists, err := store.LoadEndpointHealth(context.Background(), account.ID, CandidateOptions{}, now.Add(time.Second))
	if err != nil || !exists || !loaded.Selectable(now.Add(time.Second)) {
		t.Fatalf("stored health=%+v exists=%v err=%v", loaded, exists, err)
	}
}

func TestScannerBoundsOptionsTimeoutAndRunnerErrors(t *testing.T) {
	now := time.Date(2026, 9, 1, 18, 0, 0, 0, time.UTC)
	store, account, _ := storedCandidate(t, 43)
	for _, options := range []ScanOptions{
		{}, {ServiceID: "Telegram"}, {ServiceID: "telegram", Attempts: 4},
		{ServiceID: "telegram", AttemptTimeout: time.Hour}, {ServiceID: "telegram", EvidenceTTL: 25 * time.Hour},
	} {
		if _, err := (Scanner{Runner: &mockScanRunner{t: t}}).Scan(context.Background(), store, account.ID, options); !errors.Is(err, ErrScannerOptions) {
			t.Fatalf("invalid scan options accepted: %+v err=%v", options, err)
		}
	}
	runner := &mockScanRunner{t: t, now: now.Add(-5 * time.Second), cleanup: true, errAt: 1}
	report, err := (Scanner{Runner: runner, Now: func() time.Time { return now }}).Scan(context.Background(), store, account.ID, ScanOptions{ServiceID: "telegram"})
	if !errors.Is(err, ErrScannerRunner) || report.Verified || report.ReasonCode != "runner-failed" || len(runner.requests) != 1 || strings.Contains(err.Error(), "private runner detail") {
		t.Fatalf("runner error handling report=%+v err=%v", report, err)
	}
	lateFailure := &mockScanRunner{t: t, now: now.Add(-5 * time.Second), cleanup: true, errAt: 3}
	report, err = (Scanner{Runner: lateFailure, Now: func() time.Time { return now }, Wait: func(context.Context, time.Duration) error { return nil }}).Scan(context.Background(), store, account.ID, ScanOptions{ServiceID: "telegram", Attempts: 3})
	if !errors.Is(err, ErrScannerRunner) || report.Verified || report.ReasonCode != "runner-failed" || report.Passes < 2 {
		t.Fatalf("late runner error promoted earlier passes: report=%+v err=%v", report, err)
	}
	blocking := &mockScanRunner{t: t, block: true}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := (Scanner{Runner: blocking}).Scan(ctx, store, account.ID, ScanOptions{ServiceID: "telegram", AttemptTimeout: time.Second}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("scan cancellation was hidden", err)
	}
}

func TestScannerRunsExplicitReviewedWireGuardWithoutStore(t *testing.T) {
	now := time.Date(2026, 9, 2, 8, 0, 0, 0, time.UTC)
	runner := &mockScanRunner{t: t, now: now.Add(-5 * time.Second), cleanup: true}
	scanner := Scanner{Runner: runner, Now: func() time.Time { return now }, Wait: func(context.Context, time.Duration) error { return nil }}
	options := ScanOptions{ServiceID: "telegram", Attempts: 2, AttemptTimeout: time.Second, EvidenceTTL: time.Minute}
	report, err := scanner.ScanReviewedWireGuard(context.Background(), reviewedWGFixture("162.159.192.1:2408"), true, options)
	if err != nil || !report.Verified || len(runner.requests) != 2 {
		t.Fatalf("reviewed scan report=%+v calls=%d err=%v", report, len(runner.requests), err)
	}
	if runner.candidateSeen[0].Endpoint != "162.159.192.1:2408" {
		t.Fatal("reviewed candidate identity was not pinned")
	}
	before := len(runner.requests)
	report, err = scanner.ScanReviewedWireGuard(context.Background(), reviewedWGFixture("162.159.192.1:2408"), false, options)
	if !errors.Is(err, ErrReviewedCandidate) || report.Verified || len(runner.requests) != before {
		t.Fatalf("implicit reviewed scan report=%+v calls=%d err=%v", report, len(runner.requests), err)
	}
}

func TestScannerRunsPinnedHostnameReviewWithoutSecondLookup(t *testing.T) {
	now := time.Now().UTC()
	profile := reviewedWGFixture("engage.cloudflareclient.com:2408")
	lookups := 0
	review, err := ReviewWireGuardEndpoint(context.Background(), profile, func(context.Context, string) ([]netip.Addr, error) {
		lookups++
		return []netip.Addr{netip.MustParseAddr("162.159.192.1")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	runner := &mockScanRunner{t: t, now: now.Add(-5 * time.Second), cleanup: true}
	scanner := Scanner{Runner: runner, Now: func() time.Time { return now }, Wait: func(context.Context, time.Duration) error { return nil }}
	report, err := scanner.ScanResolvedWireGuard(context.Background(), profile, review, "162.159.192.1", true, ScanOptions{ServiceID: "telegram", Attempts: 2, AttemptTimeout: time.Second, EvidenceTTL: time.Minute})
	if err != nil || !report.Verified || len(runner.requests) != 2 || lookups != 1 || runner.candidateSeen[0].Endpoint != "162.159.192.1:2408" {
		t.Fatalf("resolved report=%+v requests=%d lookups=%d endpoint=%v err=%v", report, len(runner.requests), lookups, runner.candidateSeen, err)
	}
}
