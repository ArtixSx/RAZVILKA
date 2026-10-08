package strategylab

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
)

func TestManualSelectionIntentDoesNotAwardEvidenceOrHealth(t *testing.T) {
	previous := Selection{CandidateID: "previous", Healthy: true, Confidence: 1, LastHealthyAt: packTime.Format(time.RFC3339), RolledBackAt: "old", RollbackReason: "old", ConsecutiveFailures: 3}
	selection := manualSelection("youtube", "tcp", "ipv4", "chosen", previous, packTime)
	if selection.Mode != ModeManual || !selection.Frozen || selection.Status != "manual-unchecked" || selection.Reason != manualSelectionUncheckedReason || selection.PreviousCandidateID != "previous" || selection.SelectedAt != packTime.Format(time.RFC3339) {
		t.Fatalf("manual intent lost its explicit pending identity: %+v", selection)
	}
	if selection.Healthy || selection.Confidence != 0 || selection.LastHealthyAt != "" || selection.RolledBackAt != "" || selection.RollbackReason != "" || selection.ConsecutiveFailures != 0 {
		t.Fatalf("manual intent inherited unrelated health: %+v", selection)
	}
	if same := manualSelection("youtube", "tcp", "ipv4", "chosen", selection, packTime); same.PreviousCandidateID != "" {
		t.Fatal("reselecting the same candidate manufactured a previous candidate")
	}
}

// These are display/evidence models, never production compatibility or runtime
// authorization. No modeled observation is submitted to SelectManual.
func TestManualSelectionSnapshotPreservesUncheckedUntilReputationEvidence(t *testing.T) {
	now := packTime
	selection := manualSelection("youtube", "tcp", "ipv4", "chosen", Selection{}, now)
	for _, kind := range []string{"none", "local-error", "inconclusive", "stale", "future", "invalid", "other-candidate", "other-service", "other-family", "other-protocol", "service-fail", "pass"} {
		t.Run(kind, func(t *testing.T) {
			state := emptyState()
			key := selectionKey(selection.ServiceID, selection.Protocol, selection.IPFamily)
			state.Selections[key] = selection
			e := Evidence{CandidateID: selection.CandidateID, ServiceID: selection.ServiceID, Protocol: selection.Protocol, IPFamily: selection.IPFamily, CheckedAt: now.Format(time.RFC3339), Outcome: OutcomePass, Success: true, RouteConfirmed: true}
			switch kind {
			case "local-error":
				e.Outcome, e.Success = OutcomeLocalError, false
			case "inconclusive":
				e.Outcome, e.Success, e.RouteConfirmed = OutcomeInconclusive, false, false
			case "stale":
				e.CheckedAt = now.Add(-EvidenceFreshness - time.Second).Format(time.RFC3339)
			case "future":
				e.CheckedAt = now.Add(time.Second).Format(time.RFC3339)
			case "invalid":
				e.RouteConfirmed = false
			case "other-candidate":
				e.CandidateID = "different"
			case "other-service":
				e.ServiceID = "different"
			case "other-family":
				e.IPFamily = "ipv6"
			case "other-protocol":
				e.Protocol = "quic"
			case "service-fail":
				e.Outcome, e.Success = OutcomeServiceFail, false
			}
			if kind != "none" {
				state.Evidence = append(state.Evidence, e)
			}
			before, _ := json.Marshal(state)
			got := selectionsWithHealth(state, summarize(state, now), now)
			if len(got) != 1 || got[0].Mode != ModeManual || !got[0].Frozen || got[0].Healthy {
				t.Fatalf("unproven choice became healthy or lost manual identity: %+v", got)
			}
			wantPending := kind != "service-fail" && kind != "pass" && kind != "stale"
			if wantPending && (got[0].Status != manualSelectionUncheckedStatus || got[0].Reason != manualSelectionUncheckedReason || got[0].Confidence != 0 || got[0].ConsecutiveFailures != 0) {
				t.Fatalf("no usable evidence was presented as degraded/healthy: %+v", got[0])
			}
			if !wantPending && got[0].Status != "frozen-degraded" {
				t.Fatalf("actual incomplete/failing evidence stayed unchecked: %+v", got[0])
			}
			after, _ := json.Marshal(state)
			if !bytes.Equal(before, after) {
				t.Fatal("display normalization mutated the authoritative source")
			}
		})
	}
	state := emptyState()
	state.Selections[selectionKey("youtube", "tcp", "ipv4")] = selection
	for i := 0; i < RequiredPasses; i++ {
		state.Evidence = append(state.Evidence, Evidence{CandidateID: "chosen", ServiceID: "youtube", Protocol: "tcp", IPFamily: "ipv4", CheckedAt: now.Add(-time.Duration(i) * time.Second).Format(time.RFC3339), Outcome: OutcomePass, Success: true, RouteConfirmed: true})
	}
	got := selectionsWithHealth(state, summarize(state, now), now)
	if !got[0].Healthy || got[0].Status != "frozen-healthy" || got[0].Confidence != 1 {
		t.Fatalf("genuine eligible evidence display changed: %+v", got[0])
	}
}

func TestSelectManualRefusesDetachedOrAbsentRuntimeWithoutWriting(t *testing.T) {
	m, r := selectedReviewSourceFixture(t)
	m.Executor = &fakeProbeExecutor{}
	before := compatibilityStoreBytes(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, runtime := range []*components.ManagedNFQWSRuntimeLease{nil, {}} {
		if choice, err := m.SelectManual(ctx, "youtube", "tcp", "ipv4", r.binding.candidate.ID, runtime); err == nil || choice.CandidateID != "" {
			t.Fatal("source DTO/model supplied a public manual admission", err)
		}
	}
	if !bytes.Equal(before, compatibilityStoreBytes(t, m)) || m.Executor.(*fakeProbeExecutor).called || len(m.state.Evidence) != 0 {
		t.Fatal("refused manual choice wrote state or executed a probe")
	}
	if _, err := m.Select("youtube", "tcp", "ipv4", r.binding.candidate.ID, true); err == nil {
		t.Fatal("existing automatic selection accepted compatibility without eligible evidence")
	}
}

func TestSelectedCandidateProspectiveSourceModelCannotSupplySavedChoiceOrOwners(t *testing.T) {
	m, r := selectedReviewSourceFixture(t)
	delete(m.state.Selections, selectionKey("youtube", "tcp", "ipv4"))
	if err := m.saveLocked(); err != nil {
		t.Fatal(err)
	}
	// Observe the model's actual rewritten source without manufacturing runtime
	// or managed retirement. The prospective source leaf is not public admission.
	r.image = compatibilityImageCopy(m.image)
	var err error
	r.file, err = selectedReviewFileIdentity(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := r.candidateSourceLocked(ctx); err != nil {
		t.Fatal("unchanged prospective source model failed", err)
	}
	if r.sourceLocked(ctx) == nil || r.currentLocked(ctx) == nil || r.manualChoiceCurrentLocked(ctx) == nil {
		t.Fatal("prospective source model issued a saved review or manual owner")
	}
}

func TestManualSelectionResetAndDeleteRevokeOriginalSourceModel(t *testing.T) {
	for _, action := range []string{"reset", "delete"} {
		t.Run(action, func(t *testing.T) {
			m, r := selectedReviewSourceFixture(t)
			r.selection.Mode, r.selection.Status = ModeManual, manualSelectionUncheckedStatus
			m.state.Selections[selectionKey("youtube", "tcp", "ipv4")] = r.selection
			if err := m.saveLocked(); err != nil {
				t.Fatal(err)
			}
			r.image = compatibilityImageCopy(m.image)
			var err error
			r.file, err = selectedReviewFileIdentity(m.Path)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := selectedReviewSourceCall(m, r, ctx); err != nil {
				t.Fatal("unchanged manual source model refused before revocation", err)
			}
			if action == "reset" {
				if err := m.ResetSelection("youtube", "tcp", "ipv4"); err != nil {
					t.Fatal(err)
				}
			} else if err := m.DeleteCandidate(r.binding.candidate.ID); err != nil {
				t.Fatal(err)
			}
			if len(m.state.Selections) != 0 || selectedReviewSourceCall(m, r, ctx) == nil {
				t.Fatal("reset/delete retained the manual choice or original source review")
			}
		})
	}
}

func TestManualSelectionCannotAutomaticallyRollback(t *testing.T) {
	m, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	m.Now = func() time.Time { return packTime }
	key := selectionKey("youtube", "tcp", "ipv4")
	selection := manualSelection("youtube", "tcp", "ipv4", "chosen", Selection{}, packTime.Add(-time.Minute))
	selection.Frozen = false // Manual mode still blocks automatic mutation.
	m.state.Selections[key] = selection
	for i := 0; i < RequiredPasses; i++ {
		m.state.Evidence = append(m.state.Evidence, Evidence{CandidateID: "alternative", ServiceID: "youtube", Protocol: "tcp", IPFamily: "ipv4", CheckedAt: packTime.Format(time.RFC3339), Success: true, RouteConfirmed: true, Outcome: OutcomePass})
	}
	failure := Evidence{CandidateID: "chosen", ServiceID: "youtube", Protocol: "tcp", IPFamily: "ipv4", CheckedAt: packTime.Format(time.RFC3339), RouteConfirmed: true, Outcome: OutcomeServiceFail}
	for i := 0; i < RollbackFailures; i++ {
		m.state.Evidence = append(m.state.Evidence, failure)
	}
	m.reconcileSelectionLocked(failure)
	if m.state.Selections[key] != selection {
		t.Fatal("manual intent was automatically switched to an eligible alternative")
	}
}
