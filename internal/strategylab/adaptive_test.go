package strategylab

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

type adaptiveProbeFunc func(context.Context, Candidate, ProbeTarget) (Evidence, error)

func (f adaptiveProbeFunc) Execute(ctx context.Context, c Candidate, target ProbeTarget) (Evidence, error) {
	return f(ctx, c, target)
}

func adaptiveFixture(t *testing.T) (*AdaptiveSelector, AdaptiveRequest, *int) {
	t.Helper()
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	candidate, err := buildCandidate(CandidateInput{PoolID: "tcp-tls", Name: "reviewed", Arguments: "--filter-tcp=443 --lua-desync=fake:blob=0x00000000"}, now)
	if err != nil {
		t.Fatal(err)
	}
	calls := new(int)
	s := &AdaptiveSelector{Validator: fakeValidator{result: Validation{OK: true, Native: true, LuaChecked: true}}, Resources: fakeResourceInspector{budget: ResourceBudget{Allowed: true}}, Now: func() time.Time { return now }}
	s.Executor = adaptiveProbeFunc(func(ctx context.Context, c Candidate, target ProbeTarget) (Evidence, error) {
		*calls++
		return Evidence{CandidateID: c.ID, ServiceID: target.ServiceID, Protocol: target.Protocol, IPFamily: target.IPFamily, Success: true, RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339), Stages: []StageEvidence{{Stage: "read", Status: "pass"}}}, nil
	})
	r := AdaptiveRequest{Mode: ModePreferred, NetworkID: "wan-1", Target: ProbeTarget{ServiceID: "video", Protocol: "tcp", IPFamily: "ipv4"}, Candidates: []Candidate{candidate}, VLESSAllowed: true, VLESSFreshVerified: true}
	return s, r, calls
}

func TestAdaptiveModesNeverImplicitlyAuto(t *testing.T) {
	for _, mode := range []AdaptiveMode{ModeManual, ModeOnly, ModePreferred, "auto", ""} {
		t.Run(string(mode), func(t *testing.T) {
			s, r, calls := adaptiveFixture(t)
			r.Mode, r.RequiredLevel = mode, LevelVoice
			before := r.Candidates[0]
			result, err := s.Evaluate(context.Background(), r)
			if mode == "" || mode == "auto" {
				if err == nil || *calls != 0 {
					t.Fatal("unknown mode started automatic work")
				}
				return
			}
			if err != nil || result.Mode != mode || !reflect.DeepEqual(before, r.Candidates[0]) {
				t.Fatalf("changed strategy/mode: %+v err=%v", result, err)
			}
			if mode == ModeManual && (*calls != 0 || result.FallbackEligible) {
				t.Fatal("manual triggered adaptation/fallback")
			}
			if result.CandidateID != "" || result.FallbackEligible != (mode == ModePreferred) {
				t.Fatalf("web pass promoted to voice or only escaped to VLESS: %+v", result)
			}
		})
	}
}

func TestAdaptiveFallbackRequiresBothConsentAndFreshReserve(t *testing.T) {
	for _, allow := range []bool{true, false} {
		for _, verified := range []bool{true, false} {
			s, r, _ := adaptiveFixture(t)
			r.VLESSAllowed, r.VLESSFreshVerified, r.RequiredLevel = allow, verified, LevelMedia
			result, err := s.Evaluate(context.Background(), r)
			if err != nil || result.FallbackEligible != (allow && verified) {
				t.Fatalf("fallback authorization lost: %+v %v", result, err)
			}
		}
	}
}

func TestAdaptiveConfirmedCandidateAndExactCooldownBoundary(t *testing.T) {
	s, r, calls := adaptiveFixture(t)
	now := s.now()
	s.Now = func() time.Time { return now }
	result, err := s.Evaluate(context.Background(), r)
	if err != nil || result.Code != "candidate-ready" || result.CandidateID == "" || *calls != RequiredPasses || result.FallbackEligible {
		t.Fatalf("candidate was not confirmed: %+v %v calls=%d", result, err, *calls)
	}
	now = result.RetryAt.Add(-time.Nanosecond)
	blocked, _ := s.Evaluate(context.Background(), r)
	if blocked.Code != "cooldown" || *calls != RequiredPasses {
		t.Fatal("cooldown expired too early")
	}
	now = result.RetryAt
	ready, err := s.Evaluate(context.Background(), r)
	if err != nil || ready.Code != "candidate-ready" || *calls != 2*RequiredPasses {
		t.Fatalf("cooldown exact boundary failed: %+v %v", ready, err)
	}
}

func TestAdaptiveBoundsDuplicatesManualAndIncompatibleCandidates(t *testing.T) {
	s, r, calls := adaptiveFixture(t)
	s.Validator = fakeValidator{result: Validation{OK: true, Native: true}} // dry-run lacks Lua proof
	for i := 0; i < 20; i++ {
		candidate := r.Candidates[0]
		candidate.ID = fmt.Sprintf("st-%d", i)
		r.Candidates = append(r.Candidates, candidate, candidate)
	}
	result, err := s.Evaluate(context.Background(), r)
	if err != nil || len(result.Attempts) != MaxAdaptiveCandidates || *calls != 0 {
		t.Fatalf("unbounded or incompatible probes: %+v %v", result, err)
	}
	s, r, calls = adaptiveFixture(t)
	r.Candidates[0].Arguments = "--lua-init=@/custom.lua --lua-desync=luaexec:code=reboot()"
	before := r.Candidates[0]
	result, err = s.Evaluate(context.Background(), r)
	if err != nil || result.Attempts[0].Code != "manual-strategy" || *calls != 0 || !reflect.DeepEqual(before, r.Candidates[0]) {
		t.Fatal("custom strategy was executed/overwritten")
	}
}

func TestAdaptiveStopWhileProbeRunsDoesNotRecommendFallback(t *testing.T) {
	s, r, _ := adaptiveFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	s.Executor = adaptiveProbeFunc(func(ctx context.Context, c Candidate, target ProbeTarget) (Evidence, error) {
		close(started)
		<-ctx.Done()
		close(release) // represents completed cleanup
		return Evidence{}, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan AdaptiveResult)
	go func() {
		result, err := s.Evaluate(ctx, r)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Stop did not propagate cancellation: %v", err)
		}
		done <- result
	}()
	<-started
	concurrent, err := s.Evaluate(context.Background(), r)
	if err != nil || concurrent.Code != "cooldown" {
		t.Fatal("concurrent probe was admitted")
	}
	other := r
	other.Target.ServiceID = "other-service"
	concurrent, err = s.Evaluate(context.Background(), other)
	if err != nil || concurrent.Code != "busy" || concurrent.FallbackEligible {
		t.Fatal("another service started a parallel validation batch")
	}
	cancel()
	select {
	case result := <-done:
		<-release
		if result.CandidateID != "" || result.FallbackEligible || result.Code != "cancelled" {
			t.Fatalf("cancelled recommendation escaped: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop failed to finish")
	}
}

func TestAdaptiveLocalErrorAndInvalidEvidenceNeverSelect(t *testing.T) {
	for _, kind := range []string{"preflight", "cleanup", "wrong-service", "future", "stale"} {
		t.Run(kind, func(t *testing.T) {
			s, r, _ := adaptiveFixture(t)
			original := s.Executor
			s.Executor = adaptiveProbeFunc(func(ctx context.Context, c Candidate, target ProbeTarget) (Evidence, error) {
				e, err := original.Execute(ctx, c, target)
				switch kind {
				case "wrong-service":
					e.ServiceID = "other"
				case "future":
					e.CheckedAt = s.now().Add(time.Hour).Format(time.RFC3339)
				case "stale":
					e.CheckedAt = s.now().Add(-EvidenceFreshness - time.Second).Format(time.RFC3339)
				default:
					e.Stages = append(e.Stages, StageEvidence{Stage: kind, Status: "fail"})
				}
				return e, err
			})
			result, err := s.Evaluate(context.Background(), r)
			if err != nil || result.CandidateID != "" || len(result.Attempts) != 1 {
				t.Fatalf("invalid/local observation selected: %+v %v", result, err)
			}
		})
	}
}

func TestAdaptiveDeadlineCoversValidation(t *testing.T) {
	s, r, calls := adaptiveFixture(t)
	s.Limits = DefaultAdaptiveLimits()
	s.Limits.Budget = 5 * time.Millisecond
	s.Validator = deadlineValidator{}
	result, err := s.Evaluate(context.Background(), r)
	if !errors.Is(err, context.DeadlineExceeded) || *calls != 0 || result.FallbackEligible {
		t.Fatalf("budget did not cancel validation: %+v %v", result, err)
	}
}

func TestAdaptivePersistedCooldownFrozenAndResources(t *testing.T) {
	for _, kind := range []string{"persisted", "frozen", "low-memory", "missing-resource-inspector"} {
		t.Run(kind, func(t *testing.T) {
			s, r, calls := adaptiveFixture(t)
			switch kind {
			case "persisted":
				r.NotBefore = s.now().Add(time.Minute)
			case "frozen":
				r.Frozen = true
			case "low-memory":
				s.Resources = fakeResourceInspector{budget: ResourceBudget{Observed: true, MemoryTotalKB: 128 * 1024, MemoryAvailableKB: 1024}}
			case "missing-resource-inspector":
				s.Resources = nil
			}
			result, err := s.Evaluate(context.Background(), r)
			if err != nil || *calls != 0 || result.CandidateID != "" {
				t.Fatalf("gate admitted network work: %+v %v", result, err)
			}
			if (kind == "persisted" || kind == "frozen") && result.FallbackEligible {
				t.Fatal("cooldown/manual admitted fallback")
			}
		})
	}
}

func TestSystemProbeWaitingStopReturnsPromptly(t *testing.T) {
	x := &SystemProbeExecutor{}
	// Represent a previous probe still holding the queue during cleanup.
	x.gateOnce.Do(func() { x.gate = make(chan struct{}, 1) })
	x.gate <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := x.Execute(ctx, Candidate{}, ProbeTarget{}); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("queued probe did not honor Stop: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued probe waits for unrelated cleanup despite Stop")
	}
	<-x.gate
}

type deadlineValidator struct{}

func (deadlineValidator) Validate(ctx context.Context, _ []string) Validation {
	<-ctx.Done()
	return Validation{Code: "VALIDATION_CANCELLED"}
}

func TestAdaptiveAtMostTwelveProbesWithoutSpinning(t *testing.T) {
	s, r, _ := adaptiveFixture(t)
	seed := r.Candidates[0]
	r.Candidates = nil
	for i := 0; i < 5; i++ {
		c := seed
		c.ID = fmt.Sprintf("st-%d", i)
		r.Candidates = append(r.Candidates, c)
	}
	perCandidate := map[string]int{}
	total := 0
	s.Executor = adaptiveProbeFunc(func(ctx context.Context, c Candidate, target ProbeTarget) (Evidence, error) {
		perCandidate[c.ID]++
		total++
		success := perCandidate[c.ID] < RequiredPasses
		return Evidence{CandidateID: c.ID, ServiceID: target.ServiceID, Protocol: target.Protocol, IPFamily: target.IPFamily, Success: success, RouteConfirmed: true, CheckedAt: s.now().Format(time.RFC3339), Stages: []StageEvidence{{Stage: "read", Status: map[bool]string{true: "pass", false: "fail"}[success]}}}, nil
	})
	result, err := s.Evaluate(context.Background(), r)
	if err != nil || result.Code != "bounded-exhausted" || total != MaxAdaptiveCandidates*RequiredPasses || len(perCandidate) != MaxAdaptiveCandidates || result.CandidateID != "" {
		t.Fatalf("probe budget spun or overran: %+v err=%v probes=%d", result, err, total)
	}
}
