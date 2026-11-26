package strategylab

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCompatibilityRequiresProviderAndCancelsBeforeInvocation(t *testing.T) {
	v := CompatibleValidator{Binary: "never-execute", TrustedAssets: true, BaseArguments: compatibilityBase(t.TempDir())}
	args := []string{"--lua-desync=fake:blob=0x00000000"}
	if result := v.Validate(context.Background(), args); result.Code != "SUPERVISION_REQUIRED" || result.OK || result.LuaChecked || result.QuiescenceUnknown {
		t.Fatalf("no-provider validator performed/accepted work: %+v", result)
	}
	v.Provider = compatibilityProviderFunc(func(context.Context, string, ...string) (CompatibilityCompletion, error) {
		t.Fatal("cancelled invocation was started")
		return CompatibilityCompletion{}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result := v.Validate(ctx, args); result.Code != "VALIDATION_CANCELLED" || result.OK || result.QuiescenceUnknown {
		t.Fatalf("pre-start cancellation was misclassified: %+v", result)
	}
}

func TestCompatibilityUnknownAfterDryRunOrLuaNeverConfirms(t *testing.T) {
	for _, phase := range []string{"dry-run", "lua-init"} {
		t.Run(phase, func(t *testing.T) {
			calls := 0
			v := CompatibleValidator{Binary: "fixture-only", TrustedAssets: true, BaseArguments: compatibilityBase(t.TempDir()), Provider: compatibilityProviderFunc(func(_ context.Context, _ string, args ...string) (CompatibilityCompletion, error) {
				calls++
				if phase == "lua-init" && args[0] == "--dry-run" {
					return CompatibilityCompletion{Started: true, Quiescent: true}, nil
				}
				return CompatibilityCompletion{Started: true}, nil // zero exit without tree proof
			})}
			result := v.Validate(context.Background(), []string{"--lua-desync=fake:blob=0x00000000"})
			if result.Code != "QUIESCENCE_UNKNOWN" || !result.QuiescenceUnknown || result.OK || result.Native || result.LuaChecked || (phase == "dry-run" && calls != 1) || (phase == "lua-init" && calls != 2) {
				t.Fatalf("unknown invocation became compatible: %+v calls=%d", result, calls)
			}
		})
	}
}

func TestCompatibilityBoundsProviderIgnoringStop(t *testing.T) {
	release := make(chan struct{})
	done := make(chan struct{})
	v := CompatibleValidator{Binary: "fixture-only", TrustedAssets: true, Timeout: 5 * time.Millisecond, BaseArguments: compatibilityBase(t.TempDir()), Provider: compatibilityProviderFunc(func(context.Context, string, ...string) (CompatibilityCompletion, error) {
		defer close(done)
		<-release // model blocked Start/Wait/pipes, never arbitrary Lua
		return CompatibilityCompletion{Started: true, Quiescent: true}, nil
	})}
	started := time.Now()
	result := v.Validate(context.Background(), []string{"--lua-desync=fake:blob=0x00000000"})
	close(release)
	<-done
	if !result.QuiescenceUnknown || result.Code != "QUIESCENCE_UNKNOWN" || result.OK || result.LuaChecked || time.Since(started) > compatibilityCleanupWait+time.Second {
		t.Fatalf("unbounded/late provider success escaped fence: %+v", result)
	}
}

func TestCompatibilityDoesNotAcceptZeroCompletion(t *testing.T) {
	v := CompatibleValidator{Binary: "fixture-only", TrustedAssets: true, BaseArguments: compatibilityBase(t.TempDir()), Provider: compatibilityProviderFunc(func(context.Context, string, ...string) (CompatibilityCompletion, error) {
		return CompatibilityCompletion{Quiescent: true}, nil
	})}
	if result := v.Validate(context.Background(), []string{"--lua-desync=fake:blob=0x00000000"}); result.OK || result.LuaChecked || result.Code != "COMPATIBILITY_REJECTED" {
		t.Fatalf("unexecuted command was accepted: %+v", result)
	}
}

func TestCompatibilityProcessFailureBeforeStartIsKnownInactive(t *testing.T) {
	p := &CompatibilityProcessProvider{}
	missing := filepath.Join(t.TempDir(), "definitely-not-installed")
	for i := 0; i < 2; i++ {
		completion, err := p.Run(context.Background(), missing)
		if err == nil || errors.Is(err, ErrCompatibilityQuiescenceUnknown) || completion.Started || !completion.Quiescent {
			t.Fatalf("known non-start was falsely unknown/accepted: %+v %v", completion, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	completion, err := p.Run(ctx, missing)
	if !errors.Is(err, context.Canceled) || completion.Started || !completion.Quiescent {
		t.Fatalf("pre-start cancellation was not inactive: %+v %v", completion, err)
	}
}

func TestAdaptiveUnknownQuiescenceBlocksNextCandidateAndFallback(t *testing.T) {
	s, r, calls := adaptiveFixture(t)
	s.Validator = fakeValidator{result: Validation{Code: "QUIESCENCE_UNKNOWN", QuiescenceUnknown: true}}
	r.Candidates = append(r.Candidates, r.Candidates[0])
	result, err := s.Evaluate(context.Background(), r)
	if !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !result.QuiescenceUnknown || result.FallbackEligible || result.CandidateID != "" || len(result.Attempts) != 1 || *calls != 0 {
		t.Fatalf("unknown validator continued/recommended fallback: %+v %v", result, err)
	}
	s.Validator = fakeValidator{result: Validation{OK: true, Native: true, LuaChecked: true}}
	r.Target.ServiceID, r.NetworkID = "other-service", "new-wan"
	r.NotBefore = time.Time{}
	result, err = s.Evaluate(context.Background(), r)
	if !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !result.QuiescenceUnknown || len(result.Attempts) != 0 || *calls != 0 {
		t.Fatalf("service/network change cleared fence: %+v %v", result, err)
	}
	s, r, calls = adaptiveFixture(t)
	r.Candidates[0].Validation.QuiescenceUnknown = true
	result, err = s.Evaluate(context.Background(), r)
	if !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !result.QuiescenceUnknown || *calls != 0 {
		t.Fatalf("retained unknown disappeared in fresh selector: %+v %v", result, err)
	}
}

func TestCompatibilityUnknownPersistsWithoutSecondJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strategy.json")
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.AddCandidate("tcp-tls", "retained", "--filter-tcp=443", "expert")
	if err != nil {
		t.Fatal(err)
	}
	m.Validator = fakeValidator{result: Validation{Code: "QUIESCENCE_UNKNOWN", QuiescenceUnknown: true}}
	if _, err := m.Validate(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	m, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Snapshot().QuiescenceUnknown {
		t.Fatal("restart erased unknown")
	}
	if _, err := m.Validate(context.Background(), c.ID); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatal("revalidation cleared fence", err)
	}
	if _, err := m.Probe(context.Background(), c.ID, ProbeTarget{}); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatal("probe admitted after unknown", err)
	}
	if err := m.DeleteCandidate(c.ID); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatal("delete cleared fence", err)
	}
	if _, err := m.AddCandidate(c.PoolID, c.Name, c.Arguments, c.Origin); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatal("reimport cleared fence", err)
	}
	if _, err := m.Select("service", "tcp", "ipv4", c.ID, false); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatal("selection admitted after unknown", err)
	}
	if len(m.Snapshot().Evidence) != 0 {
		t.Fatal("local unknown poisoned network evidence")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The previous reader decodes JSON without rejecting unknown fields, then
	// rejects any schema other than 1. Persisted unknown must reach that gate.
	var legacy struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil || legacy.SchemaVersion == SchemaVersion || m.Snapshot().SchemaVersion != compatibilityUnknownSchema {
		t.Fatalf("old reader could silently ignore unknown: schema=%d err=%v", legacy.SchemaVersion, err)
	}
}

type compatibilityValidatorFunc func(context.Context, []string) Validation

func (f compatibilityValidatorFunc) Validate(ctx context.Context, args []string) Validation {
	return f(ctx, args)
}

func TestCompatibilityManagerSerializesValidationAndProbe(t *testing.T) {
	m, err := New(filepath.Join(t.TempDir(), "strategy.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.AddCandidate("tcp-tls", "reviewed", "--filter-tcp=443", "expert")
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	m.Validator = compatibilityValidatorFunc(func(context.Context, []string) Validation {
		close(entered)
		<-release
		return Validation{QuiescenceUnknown: true, Code: "QUIESCENCE_UNKNOWN"}
	})
	done := make(chan error, 1)
	go func() {
		_, err := m.Validate(context.Background(), c.ID)
		done <- err
	}()
	<-entered
	_, busyValidation := m.Validate(context.Background(), c.ID)
	_, busyProbe := m.Probe(context.Background(), c.ID, ProbeTarget{})
	close(release)
	err = <-done
	if err != nil || !errors.Is(busyValidation, errCompatibilityBusy) || !errors.Is(busyProbe, errCompatibilityBusy) || !m.Snapshot().QuiescenceUnknown || !m.Snapshot().Candidates[0].Validation.QuiescenceUnknown {
		t.Fatalf("concurrent native admission bypassed fence: saved=%v validation=%v probe=%v snapshot=%+v", err, busyValidation, busyProbe, m.Snapshot())
	}
	reloaded, err := New(m.Path)
	if err != nil || !reloaded.Snapshot().QuiescenceUnknown {
		t.Fatalf("late result erased persisted fence: %v", err)
	}
}

func TestCompatibilityUnknownSurvivesFailedSave(t *testing.T) {
	for _, failure := range []string{"before-cas", "stale-cas"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			m, err := New(filepath.Join(root, "strategy.json"))
			if err != nil {
				t.Fatal(err)
			}
			c, err := m.AddCandidate("tcp-tls", "reviewed", "--filter-tcp=443", "expert")
			if err != nil {
				t.Fatal(err)
			}
			if failure == "before-cas" {
				blocker := filepath.Join(root, "regular-file")
				if err := os.WriteFile(blocker, []byte("owned fixture"), 0600); err != nil {
					t.Fatal(err)
				}
				m.Path = filepath.Join(blocker, "strategy.json")
			} else {
				other, err := New(m.Path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := other.AddCandidate("tcp-tls", "other writer", "--filter-tcp=443", "expert"); err != nil {
					t.Fatal(err)
				}
			}
			m.Validator = fakeValidator{result: Validation{QuiescenceUnknown: true, Code: "QUIESCENCE_UNKNOWN"}}
			if _, err := m.Validate(context.Background(), c.ID); err == nil {
				t.Fatal("fault did not reject save")
			}
			if snapshot := m.Snapshot(); !snapshot.QuiescenceUnknown || snapshot.SchemaVersion != compatibilityUnknownSchema {
				t.Fatalf("save rollback erased in-memory fence: %+v", snapshot)
			}
			if _, err := m.Validate(context.Background(), c.ID); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
				t.Fatal("validation admitted after failed unknown save", err)
			}
			if _, err := m.Probe(context.Background(), c.ID, ProbeTarget{}); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
				t.Fatal("probe admitted after failed unknown save", err)
			}
		})
	}
}

func TestCompatibilitySchemaTwoRetainsFenceWithoutCandidateFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strategy.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":2,"candidates":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddCandidate("tcp-tls", "draft", "--filter-tcp=443", "expert"); err != nil {
		t.Fatal(err)
	}
	reloaded, err := New(path)
	if err != nil || !reloaded.Snapshot().QuiescenceUnknown || reloaded.Snapshot().SchemaVersion != compatibilityUnknownSchema {
		t.Fatalf("additive draft downgraded schema/fence: %v", err)
	}
}

func TestCompatibilityUnknownPrecedesManualCooldownAndStop(t *testing.T) {
	for _, mode := range []string{"manual", "frozen", "cooldown", "stop"} {
		t.Run(mode, func(t *testing.T) {
			s, r, calls := adaptiveFixture(t)
			r.Candidates[0].Validation.QuiescenceUnknown = true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "manual":
				r.Mode = ModeManual
			case "frozen":
				r.Frozen = true
			case "cooldown":
				r.NotBefore = s.now().Add(time.Hour)
			case "stop":
				cancel()
			}
			result, err := s.Evaluate(ctx, r)
			if !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !result.QuiescenceUnknown || result.Code != "quiescence-unknown" || *calls != 0 {
				t.Fatalf("early return hid unknown: %+v %v", result, err)
			}
		})
	}
}

func TestCompatibilityRetainedUnknownStopsActiveSelector(t *testing.T) {
	for _, phase := range []string{"validation", "probe"} {
		t.Run(phase, func(t *testing.T) {
			s, r, calls := adaptiveFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			if phase == "validation" {
				s.Validator = compatibilityValidatorFunc(func(context.Context, []string) Validation {
					close(entered)
					<-release
					return Validation{OK: true, Native: true, LuaChecked: true}
				})
			} else {
				executor := s.Executor
				s.Executor = adaptiveProbeFunc(func(ctx context.Context, c Candidate, target ProbeTarget) (Evidence, error) {
					close(entered)
					<-release
					return executor.Execute(ctx, c, target)
				})
			}
			type response struct {
				result AdaptiveResult
				err    error
			}
			done := make(chan response, 1)
			go func() {
				result, err := s.Evaluate(context.Background(), r)
				done <- response{result, err}
			}()
			<-entered
			retained := r
			retained.Candidates = append([]Candidate(nil), r.Candidates...)
			retained.Candidates[0].Validation.QuiescenceUnknown = true
			result, err := s.Evaluate(context.Background(), retained)
			close(release)
			active := <-done
			wantCalls := 0
			if phase == "probe" {
				wantCalls = 1 // only the already admitted probe may finish
			}
			if !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !result.QuiescenceUnknown || !errors.Is(active.err, ErrCompatibilityQuiescenceUnknown) || !active.result.QuiescenceUnknown || active.result.CandidateID != "" || active.result.FallbackEligible || *calls != wantCalls {
				t.Fatalf("active selector bypassed retained unknown: active=%+v retained=%+v calls=%d", active, result, *calls)
			}
		})
	}
}

func TestCompatibilityUnknownRejectsLateProbeEvidence(t *testing.T) {
	m, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.AddCandidate("tcp-tls", "validated", "--filter-tcp=443", "expert")
	if err != nil {
		t.Fatal(err)
	}
	other, err := m.AddCandidate("tcp-tls", "unknown invocation", "--filter-tcp=443", "expert")
	if err != nil {
		t.Fatal(err)
	}
	m.Validator = fakeValidator{result: Validation{OK: true, Native: true}}
	if _, err := m.Validate(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	m.Resources = fakeResourceInspector{budget: ResourceBudget{MemoryAvailableKB: 128 * 1024}}
	entered, release := make(chan struct{}), make(chan struct{})
	m.Executor = adaptiveProbeFunc(func(_ context.Context, candidate Candidate, target ProbeTarget) (Evidence, error) {
		close(entered)
		<-release
		return Evidence{CandidateID: candidate.ID, ServiceID: target.ServiceID, Protocol: target.Protocol, IPFamily: target.IPFamily, Success: true, RouteConfirmed: true, Stages: []StageEvidence{{Stage: "read", Status: "pass"}}}, nil
	})
	done := make(chan error, 1)
	go func() {
		_, err := m.Probe(context.Background(), c.ID, ProbeTarget{ServiceID: "service", IPFamily: "ipv4"})
		done <- err
	}()
	<-entered
	// Model a retained/recovery fence observed after admission. Manager's busy
	// gate prevents a second native launch, and Record still must reject late data.
	m.mu.Lock()
	retained := m.state.Candidates[other.ID]
	retained.Validation.QuiescenceUnknown = true
	m.state.Candidates[other.ID] = retained
	m.mu.Unlock()
	close(release)
	lateErr := <-done
	if err != nil || !errors.Is(lateErr, ErrCompatibilityQuiescenceUnknown) || len(m.Snapshot().Evidence) != 0 || len(m.Snapshot().Selections) != 0 {
		t.Fatalf("late probe mutated fenced state: saved=%v late=%v snapshot=%+v", err, lateErr, m.Snapshot())
	}
}

// Root-only process fixture: the real Go child has a timer and owns no network
// or arbitrary Lua. The validation outcome stays unknown even after direct reap.
func TestNFQWSNativeCompatibilityProcessCancellation(t *testing.T) {
	if os.Getenv("RAZVILKA_NFQWS_PROCESS_FIXTURE") != "1" {
		t.Skip("coordinator-only real process fixture")
	}
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := &CompatibilityProcessProvider{}
	type response struct {
		completion CompatibilityCompletion
		err        error
	}
	done := make(chan response, 1)
	go func() {
		completion, err := p.Run(ctx, os.Args[0], "-test.run=^TestNFQWSCompatibilityProcessFixture$", "--", "timer", root)
		done <- response{completion, err}
	}()
	for {
		if _, err := os.Stat(filepath.Join(root, "ready")); err == nil {
			break
		}
		select {
		case r := <-done:
			t.Fatalf("fixture never started: %+v", r)
		case <-ctx.Done():
			t.Fatal("fixture startup deadline")
		case <-time.After(10 * time.Millisecond):
		}
	}
	started := time.Now()
	cancel()
	select {
	case r := <-done:
		if !r.completion.Started || r.completion.Quiescent || !errors.Is(r.err, ErrCompatibilityQuiescenceUnknown) || time.Since(started) > compatibilityCleanupWait+time.Second {
			t.Fatalf("native cancellation falsely proved quiescence/unbounded: %+v", r)
		}
	case <-time.After(compatibilityCleanupWait + time.Second):
		t.Fatal("native cancellation exceeded bound")
	}
	completion, err := p.Run(context.Background(), os.Args[0])
	if completion.Started || !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatal("sticky process fence allowed replay")
	}
}

func TestNFQWSCompatibilityProcessFixture(t *testing.T) {
	args := fixtureProcessArguments()
	if len(args) != 2 || args[0] != "timer" {
		t.Skip("process fixture child only")
	}
	if os.Getenv("RAZVILKA_NFQWS_PROCESS_FIXTURE") != "1" {
		t.Fatal("fixture requires coordinator opt-in")
	}
	if err := os.WriteFile(filepath.Join(args[1], "ready"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	<-time.NewTimer(20 * time.Second).C
}

func fixtureProcessArguments() []string {
	for i, arg := range os.Args {
		if arg == "--" {
			return os.Args[i+1:]
		}
	}
	return nil
}
