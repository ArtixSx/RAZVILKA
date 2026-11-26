package strategylab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func capturedStrategyEvidence(candidate Candidate) Evidence {
	return Evidence{CandidateID: candidate.ID, CandidateIncarnation: candidate.Incarnation, ValidationGeneration: candidate.Validation.Generation,
		ServiceID: "youtube", Protocol: "tcp", IPFamily: "ipv4", Success: true, RouteConfirmed: true, Stages: []StageEvidence{{Stage: "read", Status: "pass"}}}
}

func TestRecordRejectsUnboundAndPreviousValidationEvidence(t *testing.T) {
	m, candidate, _ := eligibleStrategyManager(t)
	late := capturedStrategyEvidence(candidate)
	current, err := m.Validate(context.Background(), candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Validation.Generation == "" || current.Validation.Generation == candidate.Validation.Generation || current.Validation.CheckedAt != candidate.Validation.CheckedAt {
		t.Fatal("same-second validation did not receive a distinct generation")
	}
	before := compatibilityStoreBytes(t, m)
	for _, kind := range []string{"previous-validation", "unbound", "foreign-incarnation"} {
		t.Run(kind, func(t *testing.T) {
			evidence := late
			if kind == "unbound" {
				evidence.CandidateIncarnation, evidence.ValidationGeneration = "", ""
			}
			if kind == "foreign-incarnation" {
				evidence.ValidationGeneration = current.Validation.Generation
				evidence.CandidateIncarnation = "ffffffffffffffffffffffffffffffff"
			}
			if err := m.Record(evidence); !errors.Is(err, errEvidenceBinding) {
				t.Fatalf("old/unbound result acquired current binding: %v", err)
			}
			if !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
				t.Fatal("rejected evidence changed the durable history")
			}
		})
	}
}

func TestProbeKeepsOriginalBindingWhenExecutorReturnsLate(t *testing.T) {
	for _, changed := range []string{"incarnation", "validation"} {
		t.Run(changed, func(t *testing.T) {
			m, original, _ := eligibleStrategyManager(t)
			m.Resources = safeProbeTestResources()
			var afterChange []byte
			m.Executor = adaptiveProbeFunc(func(_ context.Context, captured Candidate, target ProbeTarget) (Evidence, error) {
				if captured.Incarnation != original.Incarnation || captured.Validation.Generation != original.Validation.Generation {
					t.Fatal("executor did not receive the admitted source")
				}
				// Deterministic source-change fault model, not a second native
				// admission. Keep NativeOK so only the binding can reject the
				// delayed result; normal Manager validation stays serialized.
				if _, err := m.Validate(context.Background(), original.ID); !errors.Is(err, errCompatibilityBusy) {
					t.Fatal("running probe lost its validation admission", err)
				}
				m.mu.Lock()
				current := m.state.Candidates[original.ID]
				if changed == "incarnation" {
					current.Incarnation = "ffffffffffffffffffffffffffffffff"
				} else {
					current.Validation.Generation = "ffffffffffffffffffffffffffffffff"
				}
				m.state.Candidates[original.ID] = current
				err := m.saveLocked()
				m.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				afterChange = compatibilityStoreBytes(t, m)
				// The unbound executor result must be bound by Probe to captured,
				// not stamped with the source that changed during Execute.
				return Evidence{CandidateID: captured.ID, ServiceID: target.ServiceID, Protocol: target.Protocol, IPFamily: target.IPFamily,
					Success: true, RouteConfirmed: true, Stages: []StageEvidence{{Stage: "read", Status: "pass"}}}, nil
			})
			late, err := m.Probe(context.Background(), original.ID, ProbeTarget{ServiceID: "youtube", IPFamily: "ipv4"})
			if !errors.Is(err, errEvidenceBinding) || late.CandidateIncarnation != original.Incarnation || late.ValidationGeneration != original.Validation.Generation {
				t.Fatalf("late Execute was rebound to the changed source: %+v %v", late, err)
			}
			if !bytes.Equal(afterChange, compatibilityStoreBytes(t, m)) || len(m.Snapshot().Evidence) != 2*RequiredPasses || m.Snapshot().Selections[0].Healthy || m.nativeRunning {
				t.Fatal("rejected late result changed evidence, awarded health or retained admission")
			}
		})
	}
}

// This is the literal schema gate of the preceding reader (schemas 1/2/3),
// not a native compatibility/runtime model. New writer formats must fail it.
func previousStrategyReaderAccepts(data []byte) bool {
	var header struct {
		SchemaVersion int `json:"schema_version"`
	}
	if json.Unmarshal(data, &header) != nil {
		return false
	}
	return header.SchemaVersion == 1 || header.SchemaVersion == 2 || header.SchemaVersion == 3
}

func TestEvidenceSchemaOrdinaryWriterUpgradesLegacyAndRejectsOldReader(t *testing.T) {
	m, candidate, _ := eligibleStrategyManager(t)
	if m.state.SchemaVersion != 4 || previousStrategyReaderAccepts(compatibilityStoreBytes(t, m)) {
		t.Fatal("new ordinary evidence remained readable by the unbound reader")
	}
	legacy := compatibilityStoreStateClone(t, m.state)
	legacy.SchemaVersion = 1
	for id, current := range legacy.Candidates {
		current.Validation.Generation = ""
		legacy.Candidates[id] = current
	}
	for i := range legacy.Evidence {
		legacy.Evidence[i].CandidateIncarnation, legacy.Evidence[i].ValidationGeneration = "", ""
	}
	old := compatibilityStoreRawState(t, m, legacy)
	reloaded, err := New(m.Path)
	if err != nil || reloaded.state.SchemaVersion != 1 || !bytes.Equal(old.Data, compatibilityStoreBytes(t, m)) {
		t.Fatal("legacy read performed a migration", err)
	}
	reloaded.Now, reloaded.Validator = m.Now, fakeValidator{result: Validation{OK: true, Native: true, Code: "PASS"}}
	if _, err := reloaded.Validate(context.Background(), candidate.ID); err != nil {
		t.Fatal(err)
	}
	if reloaded.state.SchemaVersion != 4 || previousStrategyReaderAccepts(compatibilityStoreBytes(t, reloaded)) || len(reloaded.Snapshot().Evidence) != len(legacy.Evidence) || reloaded.Snapshot().Selections[0].Healthy {
		t.Fatal("ordinary revalidation failed to retire legacy quorum behind the new reader boundary")
	}
}

func TestEvidenceSchemaLegacySupervisedReceiptsPreserveExactFormat(t *testing.T) {
	m, session, _ := compatibilityStoreFixture(t)
	if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
		t.Fatal(err)
	}
	legacy := compatibilityStoreStateClone(t, m.state)
	legacy.SchemaVersion = 3
	m.image = compatibilityStoreRawState(t, m, legacy)
	m.state = legacy
	before := compatibilityStoreBytes(t, m)
	reopened, err := New(m.Path)
	if err != nil || !reopened.Snapshot().QuiescenceUnknown || reopened.state.SchemaVersion != 3 || !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
		t.Fatal("legacy supervised read lost its pending fence or rewrote the source", err)
	}
	compatibilityStorePublishReceipt(t, m, "reaped", 0)
	terminal, image := compatibilityStoreRead(t, m, session)
	if terminal.SchemaVersion != 3 || !compatibilityResultMatches(m.state, terminal) {
		t.Fatal("helper receipt changed the exact legacy format")
	}
	wrong := terminal
	wrong.SchemaVersion = 5
	if compatibilityResultMatches(m.state, wrong) {
		t.Fatal("helper receipt acquired permission to upgrade the source schema")
	}
	if err := compatibilityStoreAck(m, context.Background(), terminal, image); err != nil {
		t.Fatal(err)
	}
	if m.state.SchemaVersion != 3 || !m.state.CompatibilityFinalizing || !compatibilityActiveInvocation(m.state.CompatibilitySession).Acknowledged {
		t.Fatal("legacy ACK lost its exact schema or finalizing fence")
	}
}

func TestEvidenceSchemaNewSupervisedPublicationCannotDowngrade(t *testing.T) {
	for _, sourceSchema := range []int{3, 5} {
		t.Run(map[int]string{3: "legacy-finalizing", 5: "current-finalizing"}[sourceSchema], func(t *testing.T) {
			m, _, candidate, validation := compatibilityStoreFinalizationFixture(t, "lua-init", 0)
			m.state.SchemaVersion = sourceSchema
			m.image = compatibilityStoreRawState(t, m, m.state)
			validation.Generation = "33333333333333333333333333333333"
			candidate.Validation = validation
			before := compatibilityStoreBytes(t, m)
			m.compatibilityPublicationHook = func(point string) {
				if point == "prepared" && !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
					t.Fatal("format or validation changed before publication CAS")
				}
			}
			if err := compatibilityPublicationCall(m, context.Background(), candidate); err != nil {
				t.Fatal(err)
			}
			reopened, err := New(m.Path)
			if err != nil || reopened.state.SchemaVersion != 5 || reopened.Snapshot().QuiescenceUnknown || reopened.state.Candidates[candidate.ID].Validation.Generation != validation.Generation || previousStrategyReaderAccepts(compatibilityStoreBytes(t, m)) {
				t.Fatal("new validation was published in a legacy format or lost completion", err)
			}
		})
	}
}

func TestEvidenceSchemaFourRetainsUnknownFence(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "durable", true: "failed-cas"}[conflict], func(t *testing.T) {
			m, candidate, _ := eligibleStrategyManager(t)
			if m.state.SchemaVersion != 4 {
				t.Fatal("fixture did not start at schema 4")
			}
			var independent []byte
			if conflict {
				independent = compatibilityStoreRawCAS(t, m, m.image, append(append([]byte(nil), m.image.Data...), '\n')).Data
			}
			m.Validator = fakeValidator{result: Validation{QuiescenceUnknown: true, Code: "QUIESCENCE_UNKNOWN"}}
			_, err := m.Validate(context.Background(), candidate.ID)
			if conflict != (err != nil) || m.state.SchemaVersion != 2 || !m.Snapshot().QuiescenceUnknown {
				t.Fatal("schema 4 forgot ordinary unknown after validation/save restoration", err)
			}
			if conflict {
				if !bytes.Equal(independent, compatibilityStoreBytes(t, m)) {
					t.Fatal("unknown CAS overwrote an independent image")
				}
				return
			}
			reopened, err := New(m.Path)
			if err != nil || reopened.state.SchemaVersion != 2 || !reopened.Snapshot().QuiescenceUnknown {
				t.Fatal("restart forgot the durable unknown fence", err)
			}
		})
	}
}

func TestSnapshotGlobalUnknownDoesNotAwardReadiness(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "global-memory-fence", true: "failed-validation-cas"}[conflict], func(t *testing.T) {
			m, candidate, _ := eligibleStrategyManager(t)
			before := m.Snapshot()
			if conflict {
				compatibilityStoreRawCAS(t, m, m.image, append(append([]byte(nil), m.image.Data...), '\n'))
				m.Validator = fakeValidator{result: Validation{QuiescenceUnknown: true, Code: "QUIESCENCE_UNKNOWN"}}
				if _, err := m.Validate(context.Background(), candidate.ID); err == nil || m.state.SchemaVersion != 2 {
					t.Fatal("fixture did not restore the previous bound source behind the failed-CAS fence", err)
				}
			} else {
				m.compatibilityUnknown = true
			}
			if m.state.Candidates[candidate.ID].Validation.Generation != candidate.Validation.Generation {
				t.Fatal("fixture did not retain the prior NativeOK generation")
			}
			state := compatibilityStoreStateClone(t, m.state)
			disk := compatibilityStoreBytes(t, m)
			snapshot := m.Snapshot()
			if !snapshot.QuiescenceUnknown || snapshot.Selections[0].Healthy || snapshot.Selections[0].Status != "unknown" || snapshot.Selections[0].Reason == "" {
				t.Errorf("global fence was presented as known readiness: %+v", snapshot.Selections)
			}
			selection, previousSelection := snapshot.Selections[0], before.Selections[0]
			selection.Healthy, previousSelection.Healthy = false, false
			selection.Status, previousSelection.Status, selection.Reason, previousSelection.Reason = "", "", "", ""
			if !compatibilityJSONEqual(selection, previousSelection) {
				t.Error("unknown display changed selection history or measurements")
			}
			for i, summary := range snapshot.Summaries {
				if summary.Eligible || summary.Reason == "" {
					t.Errorf("global fence left an eligible summary: %+v", summary)
				}
				expected := before.Summaries[i]
				summary.Eligible, expected.Eligible = false, false
				summary.Reason, expected.Reason = "", ""
				if !compatibilityJSONEqual(summary, expected) {
					t.Error("readiness suppression changed historical measurements")
				}
			}
			if !compatibilityJSONEqual(snapshot.Evidence, before.Evidence) || !compatibilityJSONEqual(m.state, state) || !bytes.Equal(disk, compatibilityStoreBytes(t, m)) {
				t.Fatal("unknown Snapshot rewrote source, disk or history")
			}
			if _, err := m.Select("youtube", "tcp", "ipv4", candidate.ID, true); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
				t.Fatal("display suppression changed the actual selection fence", err)
			}
		})
	}
}

func TestSnapshotKnownStateDoesNotRebindHistoryAfterUnknownView(t *testing.T) {
	m, candidate, _ := eligibleStrategyManager(t)
	if _, err := m.Validate(context.Background(), candidate.ID); err != nil {
		t.Fatal(err)
	}
	// Source-only display model. Clearing this private flag issues no native
	// recovery authority; the already-published generation remains unchanged.
	m.compatibilityUnknown = true
	if snapshot := m.Snapshot(); !snapshot.QuiescenceUnknown || snapshot.Selections[0].Healthy || snapshot.Selections[0].Status != "unknown" {
		t.Fatal("unknown source was presented as a known result")
	}
	m.compatibilityUnknown = false
	if snapshot := m.Snapshot(); snapshot.QuiescenceUnknown || snapshot.Selections[0].Healthy || snapshot.Selections[0].Status == "unknown" || len(snapshot.Evidence) != 2*RequiredPasses {
		t.Fatal("known observation revived or discarded the old generation's history")
	}
	for i := 0; i < RequiredPasses; i++ {
		recordStrategyPass(t, m, candidate.ID)
		if m.Snapshot().Selections[0].Healthy != (i+1 == RequiredPasses) {
			t.Fatal("known current generation did not require its own full quorum")
		}
	}
}
