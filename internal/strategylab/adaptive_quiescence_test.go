package strategylab

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// These executors return modeled evidence/errors; no process or network runs.
type adaptiveQuiescenceCountingValidator struct {
	Validator
	calls *int
}

func (v adaptiveQuiescenceCountingValidator) Validate(ctx context.Context, args []string) Validation {
	*v.calls++
	return v.Validator.Validate(ctx, args)
}

func assertAdaptiveProbeUnknown(t *testing.T, result AdaptiveResult, err error) {
	t.Helper()
	if !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !result.QuiescenceUnknown || result.Code != "quiescence-unknown" || result.CandidateID != "" || result.FallbackEligible {
		t.Fatalf("unknown probe cleanup escaped its fence: result=%+v err=%v", result, err)
	}
}

func TestAdaptiveProbeUnknownStopsFirstOrLaterPass(t *testing.T) {
	for _, stopAt := range []int{1, 2} {
		for _, wrapping := range []string{"wrapped", "joined"} {
			t.Run(fmt.Sprintf("pass-%d-%s", stopAt, wrapping), func(t *testing.T) {
				s, request, calls := adaptiveFixture(t)
				validationCalls := 0
				s.Validator = adaptiveQuiescenceCountingValidator{Validator: s.Validator, calls: &validationCalls}
				next, err := buildCandidate(CandidateInput{PoolID: request.Candidates[0].PoolID, Name: "never tested next candidate", Arguments: request.Candidates[0].Arguments}, s.now())
				if err != nil {
					t.Fatal(err)
				}
				request.Candidates = append(request.Candidates, next)
				original := s.Executor
				cleanupErr := errors.New("modeled unconfirmed cleanup")
				s.Executor = adaptiveProbeFunc(func(ctx context.Context, candidate Candidate, target ProbeTarget) (Evidence, error) {
					evidence, err := original.Execute(ctx, candidate, target)
					if *calls != stopAt {
						return evidence, err
					}
					unknown := errors.Join(ErrCompatibilityQuiescenceUnknown, cleanupErr)
					if wrapping == "wrapped" {
						unknown = fmt.Errorf("probe completed with cleanup uncertainty: %w", unknown)
					}
					// Even positive service evidence cannot authorize fallback or a
					// candidate when the same execution reports unknown cleanup.
					return evidence, unknown
				})
				result, err := s.Evaluate(context.Background(), request)
				assertAdaptiveProbeUnknown(t, result, err)
				if !errors.Is(err, cleanupErr) || *calls != stopAt || validationCalls != 1 || len(result.Attempts) != 1 || result.Attempts[0].Code != "quiescence-unknown" || len(result.Attempts[0].Evidence) != stopAt-1 {
					t.Fatalf("unknown cleanup admitted another pass/candidate or lost its cause: result=%+v err=%v probes=%d validations=%d", result, err, *calls, validationCalls)
				}
			})
		}
	}
}

func TestAdaptiveProbeCancellationPreservesExecutionErrorAndUnknown(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(fmt.Sprintf("unknown-%t", unknown), func(t *testing.T) {
			s, request, calls := adaptiveFixture(t)
			started, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			executionErr := errors.New("modeled probe execution failure")
			s.Executor = adaptiveProbeFunc(func(probeCtx context.Context, _ Candidate, _ ProbeTarget) (Evidence, error) {
				*calls++
				close(started)
				<-release
				<-probeCtx.Done()
				if unknown {
					return Evidence{}, fmt.Errorf("cleanup after cancellation: %w", errors.Join(executionErr, ErrCompatibilityQuiescenceUnknown))
				}
				return Evidence{}, executionErr
			})
			type completion struct {
				result AdaptiveResult
				err    error
			}
			done := make(chan completion, 1)
			go func() {
				result, err := s.Evaluate(ctx, request)
				done <- completion{result: result, err: err}
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("modeled probe was never admitted")
			}
			cancel()
			unblock()
			select {
			case completed := <-done:
				if !errors.Is(completed.err, context.Canceled) || !errors.Is(completed.err, executionErr) || *calls != 1 || completed.result.CandidateID != "" || completed.result.FallbackEligible {
					t.Fatalf("cancellation replaced execution error or recommended work: result=%+v err=%v probes=%d", completed.result, completed.err, *calls)
				}
				if unknown {
					assertAdaptiveProbeUnknown(t, completed.result, completed.err)
				} else if completed.result.QuiescenceUnknown || completed.result.Code != "cancelled" {
					t.Fatalf("known cancellation became an unknown fence: %+v", completed.result)
				}
			case <-time.After(time.Second):
				t.Fatal("modeled probe cancellation did not return")
			}
		})
	}
}

func TestAdaptiveProbeUnknownSurvivesTickNetworkAndManual(t *testing.T) {
	s, request, calls := adaptiveFixture(t)
	now := s.now()
	s.Now = func() time.Time { return now }
	validationCalls := 0
	s.Validator = adaptiveQuiescenceCountingValidator{Validator: s.Validator, calls: &validationCalls}
	s.Executor = adaptiveProbeFunc(func(context.Context, Candidate, ProbeTarget) (Evidence, error) {
		*calls++
		return Evidence{}, ErrCompatibilityQuiescenceUnknown
	})
	first, err := s.Evaluate(context.Background(), request)
	assertAdaptiveProbeUnknown(t, first, err)
	for _, replay := range []string{"same-tick", "cooldown-expired", "new-network", "manual", "frozen", "persisted-cooldown"} {
		t.Run(replay, func(t *testing.T) {
			next := request
			now = first.RetryAt.Add(time.Second)
			switch replay {
			case "same-tick":
				now = first.CheckedAt
			case "new-network":
				next.NetworkID = "wan-2"
			case "manual":
				next.Mode = ModeManual
			case "frozen":
				next.Frozen = true
			case "persisted-cooldown":
				next.NotBefore = now.Add(time.Hour)
			}
			result, err := s.Evaluate(context.Background(), next)
			assertAdaptiveProbeUnknown(t, result, err)
			if *calls != 1 || validationCalls != 1 || len(result.Attempts) != 0 {
				t.Fatalf("later request replayed a probe after unknown: probes=%d validations=%d result=%+v", *calls, validationCalls, result)
			}
		})
	}
}

func TestAdaptiveKnownProbeErrorKeepsExistingFallbackAndIsNotSticky(t *testing.T) {
	for _, mode := range []AdaptiveMode{ModePreferred, ModeOnly} {
		t.Run(string(mode), func(t *testing.T) {
			s, request, calls := adaptiveFixture(t)
			now := s.now()
			s.Now = func() time.Time { return now }
			request.Mode = mode
			s.Executor = adaptiveProbeFunc(func(context.Context, Candidate, ProbeTarget) (Evidence, error) {
				*calls++
				return Evidence{}, errors.New("known preflight refusal")
			})
			for attempt := 1; attempt <= 2; attempt++ {
				result, err := s.Evaluate(context.Background(), request)
				if err != nil || result.QuiescenceUnknown || result.Code != "local-unavailable" || result.CandidateID != "" || result.FallbackEligible != (mode == ModePreferred) || *calls != attempt {
					t.Fatalf("ordinary error changed fallback or became sticky: result=%+v err=%v probes=%d", result, err, *calls)
				}
				now = result.RetryAt
			}
		})
	}
}
