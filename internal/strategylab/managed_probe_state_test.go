package strategylab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"os"
	"strings"
	"testing"
	"time"
)

type managedProbeEnvironmentFunc func(context.Context) error

func (f managedProbeEnvironmentFunc) Current(ctx context.Context) error { return f(ctx) }

func managedProbeStateFixture() State {
	state := emptyState()
	state.SchemaVersion = managedStrategySchema
	record := ManagedProbeEpochRecord{Scope: "router-output-https-tcp443-ipv4", PinnedAddress: "1.1.1.1", ID: strings.Repeat("1", 32), ServiceID: "service", CandidateID: "candidate", Incarnation: strings.Repeat("2", 32), ValidationGeneration: strings.Repeat("3", 32), NetworkID: "wan-original", PolicyDigest: strings.Repeat("a", 64), RuntimeDigest: strings.Repeat("b", 64), CriteriaDigest: strings.Repeat("c", 64)}
	state.ManagedProbeEpochs = map[string]ManagedProbeEpochRecord{managedProbeKey(record.ServiceID, record.CandidateID): record}
	state.Candidates[record.CandidateID] = Candidate{ID: record.CandidateID, Incarnation: record.Incarnation, Validation: Validation{Generation: record.ValidationGeneration, OK: true, Native: true}}
	return state
}

func TestManagedProbeSchemasRetainEpochHistoryButRestartCannotAdoptAuthority(t *testing.T) {
	state := managedProbeStateFixture()
	record := state.ManagedProbeEpochs[managedProbeKey("service", "candidate")]
	e := Evidence{CandidateID: record.CandidateID, CandidateIncarnation: record.Incarnation, ValidationGeneration: record.ValidationGeneration, ServiceID: record.ServiceID, Protocol: "tcp", IPFamily: "ipv4", ManagedEpoch: record.ID}
	e.Success, e.RouteConfirmed = true, true
	e.Stages = []StageEvidence{{Stage: "read", Status: "pass"}}
	e.CheckedAt = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	if managedEvidenceCurrent(state, e) {
		t.Fatal("persisted context strings became authority")
	}
	state.managedCurrent = map[string]string{managedProbeKey(record.ServiceID, record.CandidateID): record.ID}
	if !managedEvidenceCurrent(state, e) {
		t.Fatal("exact context comparison refused")
	}
	legacy := e
	legacy.ManagedEpoch = ""
	if managedEvidenceCurrent(state, legacy) {
		t.Fatal("legacy PASS counted as managed proof")
	}
	for i := 0; i < RequiredPasses; i++ {
		state.Evidence = append(state.Evidence, e)
	}
	state.Selections[selectionKey(record.ServiceID, "tcp", "ipv4")] = Selection{ServiceID: record.ServiceID, Protocol: "tcp", IPFamily: "ipv4", CandidateID: record.CandidateID, Frozen: true, Healthy: true, Status: "healthy"}
	if summaries := summarize(state, time.Now()); len(summaries) != 1 || !summaries[0].Eligible {
		t.Fatal("fixture did not establish current managed proof", summaries)
	}
	m, in := privateFixture(t, state)
	if ValidatePrivateSnapshot(in) != nil || len(m.observeManagedProbeEpochs()) != 0 {
		t.Fatal("restart adopted original context")
	}
	if m.state.SchemaVersion != managedStrategySchema || m.state.ManagedProbeEpochs[managedProbeKey("service", "candidate")].ID != record.ID {
		t.Fatal("historical context lost")
	}
	view := m.Snapshot()
	if len(view.Selections) != 1 || view.Selections[0].Healthy || !view.Selections[0].Frozen || view.Selections[0].CandidateID != record.CandidateID || len(view.Evidence) != RequiredPasses {
		t.Fatal("restart revived health or lost intent/history", view)
	}
	if len(view.Summaries) != 1 || view.Summaries[0].Eligible || view.Summaries[0].FreshPasses != 0 {
		t.Fatal("restart revived managed reputation", view.Summaries)
	}
	for _, version := range []int{1, 2, 3, 4, 5} {
		copy := state
		copy.SchemaVersion = version
		if validateManagedProbeState(copy) == nil {
			t.Fatal("old schema accepted stronger proof", version)
		}
	}
}

// Private lifecycle model: no process/rule admission is created by this helper.
func managedProbeSlotFixture(t *testing.T) (*Manager, *ManagedProbeEpoch) {
	t.Helper()
	m, _ := privateFixture(t, managedProbeStateFixture())
	source := &CandidateProbeReview{material: &SelectedCandidateReview{}}
	epoch := &ManagedProbeEpoch{manager: m, source: source, running: true, environment: managedProbeEnvironmentFunc(func(context.Context) error { return errors.New("WAN/runtime/criteria changed") })}
	epoch.self = epoch
	m.nativeRunning, m.managedProbe = true, epoch
	return m, epoch
}

func TestManagedProbeLateContextChangeCannotPublishAndCleanupRetiresOnlyOwnSlot(t *testing.T) {
	m, epoch := managedProbeSlotFixture(t)
	before := compatibilityImageCopy(m.image)
	e := Evidence{Success: true}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := epoch.Finish(ctx, &e, nil); err == nil {
		t.Fatal("late context change published PASS")
	}
	if m.nativeRunning || m.managedProbe != nil || !compatibilityJSONEqual(m.image, before) {
		t.Fatal("known cleanup failed to retire own slot or changed state")
	}
	copy := ManagedProbeEpoch{self: epoch, manager: m, source: epoch.source, environment: epoch.environment}
	if copy.Current(ctx) == nil {
		t.Fatal("copied context owner became current")
	}
	if epoch.Finish(ctx, &e, nil) == nil {
		t.Fatal("completed slot reused")
	}
}

func TestManagedProbeCleanupFailurePersistsUnknownWithoutSchemaDowngrade(t *testing.T) {
	m, epoch := managedProbeSlotFixture(t)
	failure := errors.New("owned rules cleanup failed")
	if err := epoch.Finish(context.Background(), nil, failure); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if !m.nativeRunning || m.managedProbe != epoch || !m.state.ManagedProbeUnknown || m.state.SchemaVersion != managedStrategySchema {
		t.Fatal("cleanup failure released owner or downgraded fence")
	}
	reopened, err := New(m.Path)
	if err != nil || !reopened.Snapshot().QuiescenceUnknown || reopened.state.SchemaVersion != managedStrategySchema {
		t.Fatal("restart cleared managed unknown", err)
	}
}

func TestManagedProbeMalformedEvidenceCannotPartiallyPublishSchemaOrEpoch(t *testing.T) {
	for _, kind := range []string{"timestamp", "outcome", "scope"} {
		t.Run(kind, func(t *testing.T) {
			state := managedProbeStateFixture()
			record := state.ManagedProbeEpochs[managedProbeKey("service", "candidate")]
			state.SchemaVersion = SchemaVersion
			state.ManagedProbeEpochs = nil
			m, _ := privateFixture(t, state)
			beforeImage := compatibilityImageCopy(m.image)
			beforeState, err := compatibilityStateCopy(m.state)
			if err != nil {
				t.Fatal(err)
			}
			e := Evidence{CandidateID: record.CandidateID, CandidateIncarnation: record.Incarnation, ValidationGeneration: record.ValidationGeneration, ServiceID: record.ServiceID, Protocol: "tcp", IPFamily: "ipv4", ManagedEpoch: record.ID, Success: true, RouteConfirmed: true, Stages: []StageEvidence{{Stage: "read", Status: "pass"}}}
			switch kind {
			case "timestamp":
				e.CheckedAt = "invalid"
			case "outcome":
				e.Outcome = "unsupported"
			case "scope":
				e.IPFamily = "unknown"
			}
			m.mu.Lock()
			err = m.publishManagedEvidenceLocked(record, e)
			m.mu.Unlock()
			if err == nil {
				t.Fatal("malformed evidence accepted")
			}
			if !compatibilityJSONEqual(m.state, beforeState) || !compatibilityJSONEqual(m.image, beforeImage) {
				t.Fatal("rejected evidence changed memory schema/epoch/image")
			}
			data, err := os.ReadFile(m.Path)
			if err != nil || !bytes.Equal(data, beforeImage.Data) {
				t.Fatal("rejected evidence changed durable state", err)
			}
		})
	}
}

func TestManagedProbeSnapshotHasOneTotalObservationBudget(t *testing.T) {
	m, _ := New("")
	m.managedEpochs = map[string]*ManagedProbeEpoch{}
	for _, key := range []string{"one", "two", "three", "four"} {
		owner := &ManagedProbeEpoch{manager: m, source: &CandidateProbeReview{}, running: true, environment: managedProbeEnvironmentFunc(func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })}
		owner.self = owner
		m.managedEpochs[key] = owner
	}
	started := time.Now()
	if current := m.observeManagedProbeEpochs(); len(current) != 0 {
		t.Fatal("unobserved contexts became current")
	}
	if elapsed := time.Since(started); elapsed > 750*time.Millisecond {
		t.Fatal("snapshot serialized per-owner timeouts", elapsed)
	}
}

func TestManagedProbeStrongFieldsCannotEnterLegacySupervisedDecoder(t *testing.T) {
	for _, version := range []int{3, 5, 7} {
		state := managedProbeStateFixture()
		session := compatibilityRecordFixture(t)
		state.SchemaVersion, state.CompatibilitySession, state.CompatibilityFinalizing = version, &session, true
		if version == 7 {
			record := state.ManagedProbeEpochs[managedProbeKey("service", "candidate")]
			record.ID = "invalid"
			state.ManagedProbeEpochs[managedProbeKey("service", "candidate")] = record
		}
		data, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeCompatibilityState(restorejournal.Image{Exists: true, Data: data}); err == nil {
			t.Fatal("direct helper decoder accepted malformed managed fields", version)
		}
	}
}

func TestManagedProbeAutomaticSelectedSourceRequiresOriginalContextEvenWithoutRecord(t *testing.T) {
	state := managedProbeStateFixture()
	state.ManagedProbeEpochs = nil
	candidate := state.Candidates["candidate"]
	candidate.Validation.OK, candidate.Validation.Native, candidate.Validation.LuaChecked = true, true, true
	candidate.Validation.Code = "COMPATIBLE"
	state.Candidates[candidate.ID] = candidate
	m, _ := privateFixture(t, state)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	selection := Selection{ServiceID: "service", Protocol: "tcp", IPFamily: "ipv4", CandidateID: candidate.ID, Mode: ModePreferred, Healthy: true}
	material := &SelectedCandidateReview{path: m.Path, image: compatibilityImageCopy(m.image), binding: adaptiveCandidateBinding{manager: m, candidate: candidate}, selection: selection}
	if err := material.candidateSourceLocked(ctx); !errors.Is(err, ErrManagedProbeContextRequired) {
		t.Fatal("automatic native-compatible source bypassed missing epoch", err)
	}
	selection.Mode = ModeManual
	if err := requireManagedSelectionEpoch(state, selection, nil); err != nil {
		t.Fatal("explicit manual intent wrongly requires automatic evidence", err)
	}
	legacy := state
	legacy.SchemaVersion = SchemaVersion
	selection.Mode = ModeOnly
	if err := requireManagedSelectionEpoch(legacy, selection, nil); err != nil {
		t.Fatal("legacy material contract changed", err)
	}
}

func TestManagedProbeCandidateContextsDoNotOverwriteOtherReserves(t *testing.T) {
	state := managedProbeStateFixture()
	first := state.ManagedProbeEpochs[managedProbeKey("service", "candidate")]
	second := first
	second.CandidateID = "reserve"
	second.ID = strings.Repeat("4", 32)
	second.Incarnation = strings.Repeat("5", 32)
	state.ManagedProbeEpochs[managedProbeKey(second.ServiceID, second.CandidateID)] = second
	state.managedCurrent = map[string]string{managedProbeKey(first.ServiceID, first.CandidateID): first.ID, managedProbeKey(second.ServiceID, second.CandidateID): second.ID}
	for _, record := range []ManagedProbeEpochRecord{first, second} {
		e := Evidence{CandidateID: record.CandidateID, CandidateIncarnation: record.Incarnation, ValidationGeneration: record.ValidationGeneration, ServiceID: record.ServiceID, Protocol: "tcp", IPFamily: "ipv4", ManagedEpoch: record.ID}
		if !managedEvidenceCurrent(state, e) {
			t.Fatal("other candidate destroyed this comparison context", record.CandidateID)
		}
	}
}
