package strategylab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func adaptiveIncarnationFreshReplacement(t *testing.T, old, replacement Candidate) {
	t.Helper()
	if !compatibilityHex(old.Incarnation, 32) || !compatibilityHex(replacement.Incarnation, 32) || old.Incarnation == replacement.Incarnation {
		t.Fatal("candidate incarnation is invalid or was reused")
	}
	if adaptiveCandidateIdentityEqual(old, replacement) {
		t.Fatal("new incarnation did not retire the old identity")
	}
	old.Incarnation, replacement.Incarnation = "", ""
	if !adaptiveCandidateIdentityEqual(old, replacement) {
		t.Fatal("ABA fixture changed a former identity field")
	}
}

func TestAdaptiveIncarnationBuildIsFreshWithFixedTimeAndDefinition(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	input := CandidateInput{PoolID: "tcp-tls", Name: "exact same definition", Arguments: "--filter-tcp=443 --lua-desync=fake:blob=0x00000000", Origin: "expert"}
	first, err := buildCandidate(input, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildCandidate(input, now)
	if err != nil {
		t.Fatal(err)
	}
	adaptiveIncarnationFreshReplacement(t, first, second)
	if !compatibilityJSONEqual(first.Validation, second.Validation) || first.CreatedAt != now.Format(time.RFC3339) {
		t.Fatal("incarnation generation changed the former candidate definition or draft validation")
	}
}

func TestAdaptiveIncarnationABARejectsBindingBeforeAdmission(t *testing.T) {
	for _, replacement := range []string{"delete-add", "upsert"} {
		t.Run(replacement, func(t *testing.T) {
			m, foundation, old, stale := adaptiveFoundationFixture(t)
			if replacement == "delete-add" {
				if err := m.DeleteCandidate(old.ID); err != nil {
					t.Fatal(err)
				}
			}
			current, err := m.AddCandidate(old.PoolID, old.Name, old.Arguments, old.Origin)
			if err != nil {
				t.Fatal(err)
			}
			adaptiveIncarnationFreshReplacement(t, old, current)
			calls := 0
			m.Validator = adaptiveFoundationValidatorFunc(func(context.Context, []string) Validation {
				calls++
				return Validation{Code: "MODELED_REJECTED"}
			})
			before := adaptiveFoundationBytes(t, m)
			if _, err := foundation.bind(old); !errors.Is(err, errAdaptiveCandidateChanged) {
				t.Fatal("equal former fields rebound the stale candidate", err)
			}
			if _, err := foundation.validateBound(context.Background(), stale); !errors.Is(err, errAdaptiveCandidateChanged) {
				t.Fatal("stale incarnation entered admission", err)
			}
			fresh, err := foundation.bind(current)
			if err != nil || fresh.candidate.Incarnation != current.Incarnation {
				t.Fatal("current incarnation could not bind", err)
			}
			if calls != 0 || m.nativeRunning || m.Snapshot().QuiescenceUnknown || !bytes.Equal(before, adaptiveFoundationBytes(t, m)) {
				t.Fatal("settled ABA refusal admitted work, wrote state or invented unknown")
			}
			reopened, err := New(m.Path)
			if err != nil {
				t.Fatal(err)
			}
			if !compatibilityJSONEqual(reopened.state.Candidates[old.ID], current) {
				t.Fatal("reload lost the exact current incarnation/definition")
			}
			newFoundation, err := newManagerAdaptiveFoundation(reopened)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := newFoundation.bind(reopened.state.Candidates[old.ID]); err != nil {
				t.Fatal("reload could not bind its current incarnation", err)
			}
		})
	}
}

func TestAdaptiveIncarnationABADuringLegacyValidationPreservesNewDraft(t *testing.T) {
	m, foundation, old, stale := adaptiveFoundationFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(finish)
	m.Validator = adaptiveFoundationValidatorFunc(func(context.Context, []string) Validation {
		close(entered)
		<-release
		// A modeled rejection exercises the common publication guard without
		// fabricating native compatibility or owned process quiescence proof.
		return Validation{Code: "STALE_MODELED_REJECTION"}
	})
	type result struct {
		candidate Candidate
		err       error
	}
	done := make(chan result, 1)
	go func() {
		candidate, err := m.Validate(context.Background(), old.ID)
		done <- result{candidate: candidate, err: err}
	}()
	<-entered
	if err := m.DeleteCandidate(old.ID); err != nil {
		t.Fatal(err)
	}
	current, err := m.AddCandidate(old.PoolID, old.Name, old.Arguments, old.Origin)
	if err != nil {
		t.Fatal(err)
	}
	adaptiveIncarnationFreshReplacement(t, old, current)
	if current.Validation.Code != "NATIVE_REQUIRED" || current.Validation.Native || current.Validation.OK {
		t.Fatal("replacement is not a new unvalidated draft")
	}
	before := adaptiveFoundationBytes(t, m)
	finish()
	completed := <-done
	if !errors.Is(completed.err, errAdaptiveCandidateChanged) || errors.Is(completed.err, ErrCompatibilityQuiescenceUnknown) || !compatibilityJSONEqual(completed.candidate, Candidate{}) {
		t.Fatal("stale completion published or became fabricated unknown", completed.err)
	}
	if m.nativeRunning || m.Snapshot().QuiescenceUnknown || !compatibilityJSONEqual(m.state.Candidates[old.ID], current) || !bytes.Equal(before, adaptiveFoundationBytes(t, m)) {
		t.Fatal("stale completion replaced the exact new NATIVE_REQUIRED image")
	}
	if _, err := foundation.validateBound(context.Background(), stale); !errors.Is(err, errAdaptiveCandidateChanged) {
		t.Fatal("stale binding revived after validation settled", err)
	}
	if _, err := foundation.bind(current); err != nil {
		t.Fatal("current draft cannot bind after old admission settled", err)
	}
	reopened, err := New(m.Path)
	if err != nil || !compatibilityJSONEqual(reopened.state.Candidates[old.ID], current) {
		t.Fatal("reload restored stale completion", err)
	}
}

func TestAdaptiveIncarnationBatchUpsertGetsFreshServerTokens(t *testing.T) {
	m, foundation, old, stale := adaptiveFoundationFixture(t)
	inputs := []CandidateInput{
		{PoolID: old.PoolID, Name: old.Name, Arguments: old.Arguments, Origin: old.Origin},
		{PoolID: old.PoolID, Name: old.Name, Arguments: old.Arguments, Origin: old.Origin},
	}
	imported, err := m.AddCandidates(inputs)
	if err != nil || len(imported) != 2 {
		t.Fatal("modeled migration batch failed", err)
	}
	adaptiveIncarnationFreshReplacement(t, old, imported[0])
	adaptiveIncarnationFreshReplacement(t, imported[0], imported[1])
	if !compatibilityJSONEqual(m.state.Candidates[old.ID], imported[1]) {
		t.Fatal("upsert did not persist the final new incarnation")
	}
	if _, err := foundation.validateBound(context.Background(), stale); !errors.Is(err, errAdaptiveCandidateChanged) {
		t.Fatal("batch upsert preserved a stale binding", err)
	}
}

func TestAdaptiveIncarnationPackReimportRetiresOnlyDeletedEntry(t *testing.T) {
	m := packManager(t, filepath.Join(t.TempDir(), "strategy-lab.json"))
	data := testPack(t, 1)
	first := mustPackImport(t, m, data, false)
	if len(first.CandidateIDs) != 1 || first.Added != 1 {
		t.Fatal("first pack import fixture failed")
	}
	id := first.CandidateIDs[0]
	old := adaptiveCandidateDetached(m.state.Candidates[id])
	if !compatibilityHex(old.Incarnation, 32) {
		t.Fatal("new pack candidate has no valid server incarnation")
	}
	preserved := mustPackImport(t, m, data, false)
	if preserved.Preserved != 1 || preserved.Added != 0 || !compatibilityJSONEqual(old, m.state.Candidates[id]) {
		t.Fatal("additive pack import retired an existing unchanged record")
	}
	if err := m.DeleteCandidate(id); err != nil {
		t.Fatal(err)
	}
	second := mustPackImport(t, m, data, false)
	current := m.state.Candidates[id]
	if second.Added != 1 || len(second.CandidateIDs) != 1 || second.CandidateIDs[0] != id {
		t.Fatal("deleted pack entry was not reimported")
	}
	adaptiveIncarnationFreshReplacement(t, old, current)
	reopened, err := New(m.Path)
	if err != nil || !compatibilityJSONEqual(reopened.state.Candidates[id], current) {
		t.Fatal("reimport incarnation was not persistent", err)
	}
}

func TestAdaptiveIncarnationCannotBeSuppliedByInputOrPack(t *testing.T) {
	if _, exists := reflect.TypeOf(CandidateInput{}).FieldByName("Incarnation"); exists {
		t.Fatal("candidate input accepts an incarnation")
	}
	if _, exists := reflect.TypeOf(PackEntry{}).FieldByName("Incarnation"); exists {
		t.Fatal("portable pack input accepts an incarnation")
	}
	provided := strings.Repeat("f", 32)
	var input CandidateInput
	if err := json.Unmarshal([]byte(`{"pool_id":"tcp-tls","name":"client token","arguments":"--filter-tcp=443","origin":"expert","incarnation":"`+provided+`"}`), &input); err != nil {
		t.Fatal(err)
	}
	m, err := New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	created, err := m.AddCandidates([]CandidateInput{input})
	if err != nil || len(created) != 1 || !compatibilityHex(created[0].Incarnation, 32) || created[0].Incarnation == provided {
		t.Fatal("caller-supplied JSON token became the server incarnation", err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(testPack(t, 1), &payload); err != nil {
		t.Fatal(err)
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(payload["entries"], &entries); err != nil {
		t.Fatal(err)
	}
	entries[0]["incarnation"], _ = json.Marshal(provided)
	payload["entries"], err = json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	injected, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReviewPack(injected, false, nil, packTime); !errors.Is(err, ErrPack) {
		t.Fatal("strict pack schema accepted an incarnation", err)
	}
}

func TestAdaptiveIncarnationLegacyMissingOrInvalidRemainsManualData(t *testing.T) {
	for _, token := range []string{"", "short", strings.Repeat("A", 32), strings.Repeat("g", 32)} {
		name := token
		if name == "" {
			name = "missing"
		}
		t.Run(name, func(t *testing.T) {
			m, _, candidate, _ := adaptiveFoundationFixture(t)
			candidate.Incarnation = token
			m.mu.Lock()
			m.state.Candidates[candidate.ID] = adaptiveCandidateDetached(candidate)
			err := m.saveLocked()
			m.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			before := adaptiveFoundationBytes(t, m)
			if token == "" && bytes.Contains(before, []byte(`"incarnation"`)) {
				t.Fatal("legacy missing token was silently materialized")
			}
			reopened, err := New(m.Path)
			if err != nil || !compatibilityJSONEqual(reopened.state.Candidates[candidate.ID], candidate) {
				t.Fatal("legacy candidate became unreadable or was migrated", err)
			}
			foundation, err := newManagerAdaptiveFoundation(reopened)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := foundation.bind(candidate); !errors.Is(err, errAdaptiveCandidateIncarnation) {
				t.Fatal("legacy/invalid incarnation gained automatic admission", err)
			}
			// Even package-internal construction cannot bypass the bind refusal.
			forged := adaptiveCandidateBinding{manager: reopened, candidate: candidate}
			if _, err := foundation.validateBound(context.Background(), forged); !errors.Is(err, errAdaptiveCandidateIncarnation) {
				t.Fatal("invalid private binding bypassed incarnation admission", err)
			}
			if reopened.nativeRunning || !bytes.Equal(before, adaptiveFoundationBytes(t, reopened)) || !compatibilityJSONEqual(reopened.state.Candidates[candidate.ID], candidate) {
				t.Fatal("automatic refusal modified stored manual data")
			}
			calls := 0
			reopened.Validator = adaptiveFoundationValidatorFunc(func(context.Context, []string) Validation {
				calls++
				return Validation{Code: "MANUAL_MODELED_REJECTION"}
			})
			manual, err := reopened.Validate(context.Background(), candidate.ID)
			if err != nil || calls != 1 || manual.Incarnation != token || manual.Validation.Code != "MANUAL_MODELED_REJECTION" {
				t.Fatal("manual legacy validation was blocked or assigned a token", err)
			}
			if _, err := foundation.bind(manual); !errors.Is(err, errAdaptiveCandidateIncarnation) {
				t.Fatal("manual validation manufactured automatic authority", err)
			}
			fresh, err := reopened.AddCandidate(candidate.PoolID, candidate.Name, candidate.Arguments, candidate.Origin)
			if err != nil || !compatibilityHex(fresh.Incarnation, 32) || fresh.Incarnation == token {
				t.Fatal("explicit replacement did not obtain a server incarnation", err)
			}
			if _, err := foundation.bind(fresh); err != nil {
				t.Fatal("new server-generated record could not bind", err)
			}
		})
	}
}
