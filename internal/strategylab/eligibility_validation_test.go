package strategylab

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"
)

// These fixtures exercise persisted candidate/evidence lifecycle, not native
// runtime compatibility or interception on a router.
func eligibleStrategyManager(t *testing.T) (*Manager, Candidate, Candidate) {
	t.Helper()
	m, err := New(filepath.Join(t.TempDir(), "strategies.json"))
	if err != nil {
		t.Fatal(err)
	}
	m.Now = func() time.Time { return time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC) }
	m.Validator = fakeValidator{result: Validation{OK: true, Native: true, Code: "PASS"}}
	var candidates []Candidate
	for _, name := range []string{"chosen", "unrelated"} {
		candidate, err := m.AddCandidate("tcp-tls", name, "--filter-tcp=443", "expert")
		if err != nil {
			t.Fatal(err)
		}
		candidate, err = m.Validate(context.Background(), candidate.ID)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < RequiredPasses; i++ {
			recordStrategyPass(t, m, candidate.ID)
		}
		candidates = append(candidates, candidate)
	}
	if _, err := m.Select("youtube", "tcp", "ipv4", candidates[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if !m.Snapshot().Selections[0].Healthy {
		t.Fatal("fixture did not establish a genuinely eligible current candidate")
	}
	return m, candidates[0], candidates[1]
}

func recordStrategyPass(t *testing.T, m *Manager, id string) {
	t.Helper()
	candidate := m.state.Candidates[id]
	if err := m.Record(Evidence{CandidateID: id, CandidateIncarnation: candidate.Incarnation, ValidationGeneration: candidate.Validation.Generation, ServiceID: "youtube", Protocol: "tcp", IPFamily: "ipv4",
		Success: true, RouteConfirmed: true, Stages: []StageEvidence{{Stage: "read", Status: "pass"}}}); err != nil {
		t.Fatal(err)
	}
}

func assertStrategyEvidenceRetired(t *testing.T, m *Manager, candidate, unrelated Candidate) {
	t.Helper()
	snapshot := m.Snapshot()
	if len(snapshot.Selections) != 1 || snapshot.Selections[0].CandidateID != candidate.ID || snapshot.Selections[0].Healthy {
		t.Errorf("retired probe evidence retained health or changed the user's choice: %+v", snapshot.Selections)
	}
	for _, summary := range snapshot.Summaries {
		if summary.CandidateID == candidate.ID && (summary.Eligible || summary.FreshPasses != 0 || summary.Confidence != 0 || len(summary.Coverage) != 0) {
			t.Error("historical probe evidence still contributes current reputation")
		}
	}
	if len(snapshot.Evidence) != 2*RequiredPasses {
		t.Errorf("expected both candidates' history, got %d records", len(snapshot.Evidence))
	}
	counts := map[string]int{}
	for _, evidence := range snapshot.Evidence {
		counts[evidence.CandidateID]++
	}
	if counts[candidate.ID] != RequiredPasses || counts[unrelated.ID] != RequiredPasses {
		t.Error("candidate replacement/validation discarded saved history")
	}
	if _, err := m.Select("youtube", "tcp", "ipv4", candidate.ID, true); err == nil {
		t.Error("native compatibility alone revived the old selectable probe result")
	}
}

func TestCandidateReplacementCannotReviveOldProbeEvidence(t *testing.T) {
	m, candidate, unrelated := eligibleStrategyManager(t)
	// Keep the same timestamp deliberately: second-resolution CreatedAt cannot
	// distinguish replacement from the retired candidate's real incarnation.
	replacement, err := m.AddCandidate(candidate.PoolID, candidate.Name, candidate.Arguments, candidate.Origin)
	if err != nil || replacement.ID != candidate.ID || replacement.Incarnation == candidate.Incarnation {
		t.Fatalf("replacement did not create the intended new incarnation: %+v %v", replacement, err)
	}
	assertStrategyEvidenceRetired(t, m, candidate, unrelated)
	if _, err := m.Validate(context.Background(), replacement.ID); err != nil {
		t.Fatal(err)
	}
	assertStrategyEvidenceRetired(t, m, candidate, unrelated)
	reloaded, err := New(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	reloaded.Now = m.Now
	assertStrategyEvidenceRetired(t, reloaded, candidate, unrelated)
	for i := 0; i < RequiredPasses; i++ {
		recordStrategyPass(t, reloaded, replacement.ID)
		if got := reloaded.Snapshot().Selections[0].Healthy; got != (i+1 == RequiredPasses) {
			t.Fatalf("new health did not require the full fresh quorum: pass=%d healthy=%t", i+1, got)
		}
	}
}

func TestNativeRevalidationRetiresPriorProbeEvidence(t *testing.T) {
	for _, validation := range []Validation{{Native: true, Code: "NATIVE_REJECTED"}, {OK: true, Code: "NON_NATIVE"}, {OK: true, Native: true, Code: "PASS"}} {
		t.Run(validation.Code, func(t *testing.T) {
			m, candidate, unrelated := eligibleStrategyManager(t)
			m.Validator = fakeValidator{result: validation}
			if _, err := m.Validate(context.Background(), candidate.ID); err != nil {
				t.Fatal(err)
			}
			assertStrategyEvidenceRetired(t, m, candidate, unrelated)
			m.Validator = fakeValidator{result: Validation{OK: true, Native: true, Code: "PASS"}}
			if _, err := m.Validate(context.Background(), candidate.ID); err != nil {
				t.Fatal(err)
			}
			assertStrategyEvidenceRetired(t, m, candidate, unrelated)
		})
	}
}

func TestRejectedNativeCandidateCannotBecomeRollbackAlternative(t *testing.T) {
	m, previous, active := eligibleStrategyManager(t)
	if _, err := m.Select("youtube", "tcp", "ipv4", active.ID, false); err != nil {
		t.Fatal(err)
	}
	m.Validator = fakeValidator{result: Validation{Native: true, Code: "NATIVE_REJECTED"}}
	if _, err := m.Validate(context.Background(), previous.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < RollbackFailures; i++ {
		if err := m.Record(Evidence{CandidateID: active.ID, CandidateIncarnation: active.Incarnation, ValidationGeneration: active.Validation.Generation, ServiceID: "youtube", Protocol: "tcp", IPFamily: "ipv4",
			RouteConfirmed: true, Stages: []StageEvidence{{Stage: "result", Status: "fail"}}}); err != nil {
			t.Fatal(err)
		}
	}
	selection := m.Snapshot().Selections[0]
	if selection.CandidateID != active.ID || selection.RolledBackAt != "" || selection.Healthy {
		t.Fatalf("rollback selected an alternative whose native validation failed: %+v", selection)
	}
}

func TestHistoricalPassesRequireCurrentNativeValidation(t *testing.T) {
	for _, validation := range []Validation{{Code: "NATIVE_REQUIRED"}, {Native: true, Code: "NATIVE_REJECTED"}, {OK: true, Code: "NON_NATIVE"}, {QuiescenceUnknown: true, Code: "QUIESCENCE_UNKNOWN"}} {
		t.Run(validation.Code, func(t *testing.T) {
			m, candidate, _ := eligibleStrategyManager(t)
			// Model an already-saved state from the old writer, which retained
			// its successful observations after replacing validation.
			candidate.Validation = validation
			m.state.Candidates[candidate.ID] = candidate
			if err := m.saveLocked(); err != nil {
				t.Fatal(err)
			}
			reloaded, err := New(m.Path)
			if err != nil {
				t.Fatal(err)
			}
			reloaded.Now = m.Now
			snapshot := reloaded.Snapshot()
			if snapshot.Selections[0].Healthy || snapshot.Selections[0].Reason == "" {
				t.Fatalf("historical passes overrode current validation: %+v", snapshot.Selections[0])
			}
			for _, summary := range snapshot.Summaries {
				if summary.CandidateID == candidate.ID && (summary.Eligible || summary.Passes != RequiredPasses) {
					t.Fatalf("current eligibility or historical observations are wrong: %+v", summary)
				}
			}
			if _, err := reloaded.Select("youtube", "tcp", "ipv4", candidate.ID, true); err == nil {
				t.Fatal("historical evidence admitted a currently unvalidated candidate")
			}
		})
	}
}

func TestLegacyNativePassHistoryCannotBecomeCurrentAfterRestart(t *testing.T) {
	for _, incarnation := range []string{"missing", "replaced"} {
		t.Run(incarnation, func(t *testing.T) {
			m, candidate, _ := eligibleStrategyManager(t)
			legacy := m.state
			legacy.SchemaVersion = 1
			replacement, err := buildCandidate(CandidateInput{PoolID: candidate.PoolID, Name: candidate.Name, Arguments: candidate.Arguments, Origin: candidate.Origin}, m.now())
			if err != nil {
				t.Fatal(err)
			}
			if incarnation == "missing" {
				replacement.Incarnation = ""
			}
			// An older writer could republish a native PASS in the same second
			// while retaining observations for an unrelated prior incarnation.
			replacement.Validation = Validation{OK: true, Native: true, Code: "PASS", Arguments: candidate.Validation.Arguments, CheckedAt: candidate.Validation.CheckedAt}
			legacy.Candidates[candidate.ID] = replacement
			legacy.Evidence = nil
			for i := 0; i < RequiredPasses; i++ {
				legacy.Evidence = append(legacy.Evidence, Evidence{CandidateID: candidate.ID, ServiceID: "youtube", Protocol: "tcp", IPFamily: "ipv4", Outcome: OutcomePass, Success: true, RouteConfirmed: true, CheckedAt: m.now().UTC().Format(time.RFC3339), Stages: []StageEvidence{{Stage: "read", Status: "pass"}}})
			}
			image := compatibilityStoreRawState(t, m, legacy)
			reloaded, err := New(m.Path)
			if err != nil {
				t.Fatal(err)
			}
			reloaded.Now = m.Now
			snapshot := reloaded.Snapshot()
			if snapshot.Selections[0].Healthy || snapshot.Summaries[0].Eligible || snapshot.Summaries[0].FreshPasses != 0 || snapshot.Summaries[0].Confidence != 0 || len(snapshot.Summaries[0].Coverage) != 0 {
				t.Errorf("legacy unbound PASS became current proof: %+v %+v", snapshot.Selections, snapshot.Summaries)
			}
			if len(snapshot.Evidence) != RequiredPasses || !bytes.Equal(image.Data, compatibilityStoreBytes(t, reloaded)) {
				t.Error("read-only legacy observation rewrote or discarded history")
			}
			if _, err := reloaded.Select("youtube", "tcp", "ipv4", candidate.ID, true); err == nil {
				t.Error("legacy NativeOK and unbound quorum admitted selection")
			}
		})
	}
}

func TestCandidateEvidenceRetirementDoesNotEscapeFailedCAS(t *testing.T) {
	m, candidate, _ := eligibleStrategyManager(t)
	before, err := compatibilityStateCopy(m.state)
	if err != nil {
		t.Fatal(err)
	}
	// An independent writer wins before replacement, so the complete proposed
	// candidate/evidence image must be refused without editing either image.
	independent := compatibilityStoreRawCAS(t, m, m.image, append(append([]byte(nil), m.image.Data...), '\n'))
	if _, err := m.AddCandidate(candidate.PoolID, candidate.Name, candidate.Arguments, candidate.Origin); err == nil {
		t.Fatal("stale candidate writer unexpectedly replaced an independent image")
	}
	if !compatibilityJSONEqual(m.state, before) || !bytes.Equal(compatibilityStoreBytes(t, m), independent.Data) {
		t.Fatal("failed candidate CAS removed evidence or overwrote the independent image")
	}
}

func TestSupervisedValidationChangesEvidenceGenerationAtomically(t *testing.T) {
	for _, exit := range []int{0, 7} {
		t.Run(map[int]string{0: "pass", 7: "rejected"}[exit], func(t *testing.T) {
			// Existing store-model fixture: no NFQWS process or packet admission.
			m, _, candidate, validation := compatibilityStoreFinalizationFixture(t, "lua-init", exit)
			previous := candidate
			previous.Validation = strategyEvidenceModelCandidate(candidate.ID).Validation
			m.state.Candidates[candidate.ID] = previous
			validation.Generation = "33333333333333333333333333333333"
			old := Evidence{CandidateID: candidate.ID, CandidateIncarnation: candidate.Incarnation, ValidationGeneration: previous.Validation.Generation, ServiceID: "youtube", Protocol: "tcp", IPFamily: "ipv4",
				Success: true, RouteConfirmed: true, CheckedAt: m.now().UTC().Format(time.RFC3339), Stages: []StageEvidence{{Stage: "read", Status: "pass"}}}
			other := old
			other.CandidateID = "unrelated"
			history := []Evidence{old, old, old, other}
			m.state.Evidence = history
			m.image = compatibilityStoreRawState(t, m, m.state)
			before := compatibilityStoreBytes(t, m)
			m.compatibilityPublicationHook = func(stage string) {
				if stage == "prepared" && (!compatibilityJSONEqual(m.state.Evidence, history) || m.state.Candidates[candidate.ID].Validation.Generation != previous.Validation.Generation || !bytes.Equal(before, compatibilityStoreBytes(t, m))) {
					t.Fatal("generation/history changed before the complete publication CAS")
				}
			}
			candidate.Validation = validation
			if err := compatibilityPublicationCall(m, context.Background(), candidate); err != nil {
				t.Fatal(err)
			}
			reloaded, err := New(m.Path)
			if err != nil {
				t.Fatal(err)
			}
			for _, observed := range []*Manager{m, reloaded} {
				if !compatibilityJSONEqual(observed.state.Evidence, history) || !compatibilityJSONEqual(observed.state.Candidates[candidate.ID].Validation, validation) {
					t.Fatal("candidate generation and retained history were not one durable image")
				}
				for _, summary := range observed.Snapshot().Summaries {
					if summary.CandidateID == candidate.ID && (summary.Eligible || summary.FreshPasses != 0 || summary.Confidence != 0 || len(summary.Coverage) != 0) {
						t.Fatal("new generation reused historical supervised evidence")
					}
				}
			}
		})
	}
}
