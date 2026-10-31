package strategylab

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalProbeFailuresRemainVisibleWithoutPoisoningOrRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 4, 1, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { return now }
	m.Validator = fakeValidator{result: Validation{OK: true, Native: true}}
	c, _ := m.AddCandidate("tcp-tls", "user strategy", "--filter-tcp=443", "expert")
	c, err = m.Validate(context.Background(), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	e := Evidence{CandidateID: c.ID, CandidateIncarnation: c.Incarnation, ValidationGeneration: c.Validation.Generation, ServiceID: "service", Protocol: "tcp", IPFamily: "ipv4", Success: true, RouteConfirmed: true, Stages: []StageEvidence{{Stage: "read", Status: "pass"}}}
	for i := 0; i < RequiredPasses; i++ {
		if err := m.Record(e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Select("service", "tcp", "ipv4", c.ID, false); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"preflight", "dns", "socket", "nfqws2", "firewall", "cleanup", "route"} {
		now = now.Add(time.Second)
		local := e
		local.Success, local.RouteConfirmed = false, false
		local.Stages = []StageEvidence{{Stage: stage, Status: "fail"}}
		if err := m.Record(local); err != nil {
			t.Fatal(err)
		}
	}
	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	reloaded.Now = m.Now
	snapshot := reloaded.Snapshot()
	if len(snapshot.Evidence) != RequiredPasses+7 || snapshot.Summaries[0].Failures != 0 || snapshot.Summaries[0].Confidence != 1 || !snapshot.Selections[0].Healthy || snapshot.Selections[0].ConsecutiveFailures != 0 {
		t.Fatalf("local errors poisoned strategy or disappeared on reload: %+v", snapshot)
	}
	for _, e := range snapshot.Evidence[RequiredPasses:] {
		if e.Outcome != OutcomeLocalError && e.Outcome != OutcomeInconclusive {
			t.Fatalf("local failure not typed: %+v", e)
		}
	}
}

func TestCoverageDoesNotRefreshMediaVoiceGameFromWeb(t *testing.T) {
	now := time.Date(2026, 10, 4, 1, 0, 0, 0, time.UTC)
	candidate := strategyEvidenceModelCandidate("st-1")
	old := Evidence{CandidateID: "st-1", CandidateIncarnation: candidate.Incarnation, ValidationGeneration: candidate.Validation.Generation, ServiceID: "service", Protocol: "tcp", IPFamily: "ipv4", Success: true, RouteConfirmed: true, CheckedAt: now.Add(-EvidenceFreshness - time.Second).Format(time.RFC3339), Stages: []StageEvidence{{Stage: "media", Status: "pass"}, {Stage: "voice", Status: "pass"}, {Stage: "game", Status: "pass"}}}
	fresh := old
	fresh.CheckedAt, fresh.Stages = now.Format(time.RFC3339), []StageEvidence{{Stage: "read", Status: "pass"}}
	s := summarize(State{Candidates: map[string]Candidate{candidate.ID: candidate}, Evidence: []Evidence{old, fresh}}, now)[0]
	if len(s.Coverage) != 5 {
		t.Fatalf("scenario coverage lost: %+v", s)
	}
	for _, coverage := range s.Coverage {
		if coverage.Fresh != (coverage.Level == LevelPacket || coverage.Level == LevelHTTP) {
			t.Fatalf("web observation refreshed independent scenario: %+v", coverage)
		}
	}
	fresh.Level = LevelMedia
	if normalizeEvidence(&fresh) == nil {
		t.Fatal("HTTP was relabelled as media")
	}
}

func TestFutureAndMalformedEvidenceCannotBecomeFresh(t *testing.T) {
	now := time.Date(2026, 10, 4, 1, 0, 0, 0, time.UTC)
	candidate := strategyEvidenceModelCandidate("st-1")
	for _, timestamp := range []string{"broken", now.Add(time.Hour).Format(time.RFC3339)} {
		e := Evidence{CandidateID: "st-1", CandidateIncarnation: candidate.Incarnation, ValidationGeneration: candidate.Validation.Generation, ServiceID: "service", Protocol: "tcp", IPFamily: "ipv4", Success: true, RouteConfirmed: true, CheckedAt: timestamp, Stages: []StageEvidence{{Stage: "read", Status: "pass"}}}
		s := summarize(State{Candidates: map[string]Candidate{candidate.ID: candidate}, Evidence: []Evidence{e, e, e}}, now)[0]
		if s.Eligible || s.FreshPasses != 0 || len(s.Coverage) != 0 {
			t.Fatalf("invalid timestamp became fresh: %+v", s)
		}
	}
}

func TestStaleFailureCannotRollBackFreshSelection(t *testing.T) {
	now := time.Date(2026, 10, 4, 1, 0, 0, 0, time.UTC)
	candidate := strategyEvidenceModelCandidate("st-1")
	selection := Selection{CandidateID: "st-1", ServiceID: "service", Protocol: "tcp", IPFamily: "ipv4", SelectedAt: now.Add(-48 * time.Hour).Format(time.RFC3339)}
	e := Evidence{CandidateID: "st-1", CandidateIncarnation: candidate.Incarnation, ValidationGeneration: candidate.Validation.Generation, ServiceID: "service", Protocol: "tcp", IPFamily: "ipv4", RouteConfirmed: true, Outcome: OutcomeServiceFail, CheckedAt: now.Add(-EvidenceFreshness - time.Second).Format(time.RFC3339), Stages: []StageEvidence{{Stage: "result", Status: "fail"}}}
	if failures := consecutiveFailures(State{Candidates: map[string]Candidate{candidate.ID: candidate}, Evidence: []Evidence{e, e, e}}, selection, now); failures != 0 {
		t.Fatalf("stale failures contributed to rollback quorum: %d", failures)
	}
	e.CheckedAt = now.Format(time.RFC3339)
	if failures := consecutiveFailures(State{Candidates: map[string]Candidate{candidate.ID: candidate}, Evidence: []Evidence{e, e, e}}, selection, now); failures != RollbackFailures {
		t.Fatalf("fresh definite failures no longer contribute: %d", failures)
	}
	unknown := e
	unknown.Outcome, unknown.RouteConfirmed = OutcomeInconclusive, false
	if failures := consecutiveFailures(State{Candidates: map[string]Candidate{candidate.ID: candidate}, Evidence: []Evidence{e, unknown, e}}, selection, now); failures != 1 {
		t.Fatalf("uncertainty bridged a consecutive failure quorum: %d", failures)
	}
}

func TestManagerStopDoesNotRecordLateSuccess(t *testing.T) {
	m, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	m.Resources = safeProbeTestResources()
	m.Validator = fakeValidator{result: Validation{OK: true, Native: true}}
	c, _ := m.AddCandidate("tcp-tls", "reviewed", "--filter-tcp=443", "expert")
	if _, err := m.Validate(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.Executor = adaptiveProbeFunc(func(context.Context, Candidate, ProbeTarget) (Evidence, error) {
		cancel()
		return Evidence{CandidateID: c.ID, CandidateIncarnation: c.Incarnation, ValidationGeneration: c.Validation.Generation, ServiceID: "service", Protocol: "tcp", IPFamily: "ipv4", Success: true, RouteConfirmed: true, Stages: []StageEvidence{{Stage: "read", Status: "pass"}}}, nil
	})
	if _, err := m.Probe(ctx, c.ID, ProbeTarget{ServiceID: "service", IPFamily: "ipv4"}); err != context.Canceled {
		t.Fatalf("late success survived Stop: %v", err)
	}
	if len(m.Snapshot().Evidence) != 0 {
		t.Fatal("cancelled result changed evidence store")
	}
}
