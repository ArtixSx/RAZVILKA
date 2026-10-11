//go:build linux

package physicalscope

import (
	"context"
	"errors"
	"os"
	"reflect"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Root-only read-only stock acceptance, not Apply or a cleanup capability:
// RAZVILKA_PHYSICAL_SCOPE_SELECTED_CONTINUITY_NATIVE=1
// RAZVILKA_PHYSICAL_SCOPE_NATIVE=stock-nc1812
// RAZVILKA_PHYSICAL_SCOPE_SELECTED_FILE=<absolute private Selection JSON>
// Root derives the original revision/policy_revision, exactly one segment_ids
// entry and one selected device_ids entry from actual intent. Exclusions are
// also original intent and must be freshly bound by the production observer.
// No JSON identity, observed address, snapshot or fact reader is accepted.
func TestPhysicalScopeNativeSelectedDeviceContinuity(t *testing.T) {
	if os.Getenv("RAZVILKA_PHYSICAL_SCOPE_SELECTED_CONTINUITY_NATIVE") != "1" {
		t.Skip("Root-only selected-device continuity opt-in")
	}
	if runtime.GOARCH != "arm64" || os.Getenv("RAZVILKA_PHYSICAL_SCOPE_NATIVE") != "stock-nc1812" {
		t.Fatal("selected continuity requires actual stock NC1812 on Linux ARM64")
	}
	selection, err := continuityNativePrivateSelection(os.Getenv("RAZVILKA_PHYSICAL_SCOPE_SELECTED_FILE"))
	if err == nil {
		selection, err = nativeSelectedContinuityIntent(selection)
	}
	if err != nil {
		t.Fatal("selected continuity private intent refused")
	}
	// This bounds the entire open Review to 60 seconds. Each observation also
	// gets a NEW finite operation context; the collector remains open between
	// those operations and is joined before its original socket is closed.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if deadline, ok := t.Deadline(); ok {
		bounded, finish := context.WithDeadline(ctx, deadline)
		defer finish()
		ctx = bounded
	}
	fresh := func(check func(context.Context) error) error {
		c, finish := context.WithTimeout(ctx, 12*time.Second)
		defer finish()
		return check(c)
	}
	provider, err := netidentity.NewReviewedStockNC1812Provider(ctx)
	if err != nil {
		t.Fatalf("selected continuity provider refused: %v", DiagnosticStages(err))
	}
	selectionReads := 0
	read := func(c context.Context) (Selection, error) {
		selectionReads++
		return cloneSnapshot(Snapshot{Selection: selection}).Selection, c.Err()
	}
	observer := NewReviewedStockNC1812(provider, read)
	var review *Review
	if err := fresh(func(c context.Context) error {
		var err error
		review, err = observer.Observe(c)
		return err
	}); err != nil {
		t.Fatalf("selected continuity observe refused: %v", DiagnosticStages(err))
	}
	closed := false
	defer func() {
		if !closed {
			if err := review.Close(); err != nil {
				t.Errorf("selected continuity close refused: %v", DiagnosticStages(err))
			}
		}
	}()
	original := review.Snapshot()
	if original.Identity.Kind != netidentity.ReviewedSingleInitNet || original.ReviewID == "" || len(original.Segments) != 1 || !reflect.DeepEqual(original.Selection, selection) || validateSelectedDevices(selection.SelectedDevices, original.Devices) != nil {
		t.Fatal("selected continuity original stock projection refused")
	}
	unchanged := func() {
		if !reflect.DeepEqual(original, review.Snapshot()) {
			t.Fatal("selected continuity adopted replacement facts")
		}
	}
	forwardChecks, retainedChecks := 0, 0
	checkRetained := func() {
		reads := selectionReads
		if err := fresh(func(c context.Context) error { return observer.VerifyRetainedIncarnation(c, review) }); err != nil {
			t.Fatalf("selected continuity retained refused: %v", DiagnosticStages(err))
		}
		if selectionReads != reads {
			t.Fatal("selected continuity retained reread selection")
		}
		unchanged()
		retainedChecks++
	}
	// Hold this SAME original Review for 50 seconds. Continuous notifications
	// and each fresh production current/capture must agree with its first full
	// snapshot; the first refusal ends the run without retry or replacement.
	until := time.Now().Add(50 * time.Second)
	for {
		if err := fresh(func(c context.Context) error { return observer.Verify(c, review) }); err != nil {
			t.Fatalf("selected continuity forward refused: %v", DiagnosticStages(err))
		}
		forwardChecks++
		unchanged()
		checkRetained()
		if !time.Now().Before(until) {
			break
		}
		timer := time.NewTimer(min(5*time.Second, time.Until(until)))
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal("selected continuity finite context expired")
		case <-timer.C:
		}
	}
	if forwardChecks < 2 || retainedChecks < 2 {
		t.Fatal("selected continuity did not repeat original observations")
	}
	// This changes ONLY this test's SelectionReader. It never writes the
	// private file, Store, consent or native network configuration.
	selection.Revision++
	reads := selectionReads
	err = fresh(func(c context.Context) error { return observer.Verify(c, review) })
	var refusal *failure
	if !errors.As(err, &refusal) || refusal.stage != "verify.selection.changed" || selectionReads != reads+1 {
		t.Fatalf("selected continuity selection refusal missing: %v", DiagnosticStages(err))
	}
	checkRetained()
	// Even restoring the test intent cannot renew forward admission.
	selection = cloneSnapshot(original).Selection
	reads = selectionReads
	err = fresh(func(c context.Context) error { return observer.Verify(c, review) })
	if !errors.As(err, &refusal) || refusal.stage != "verify.review.unavailable" || selectionReads != reads {
		t.Fatal("selected continuity restored intent revived forward observation")
	}
	checkRetained()
	if ctx.Err() != nil {
		t.Fatal("selected continuity finite context expired")
	}
	closed = true
	if err := review.Close(); err != nil {
		t.Fatalf("selected continuity close refused: %v", DiagnosticStages(err))
	}
	for _, check := range []struct {
		stage string
		check func(context.Context) error
	}{
		{"verify.review.unavailable", func(c context.Context) error { return observer.Verify(c, review) }},
		{"retained.review.unavailable", func(c context.Context) error { return observer.VerifyRetainedIncarnation(c, review) }},
	} {
		err := fresh(check.check)
		if !errors.As(err, &refusal) || refusal.stage != check.stage {
			t.Fatalf("selected continuity closed refusal missing: %v", DiagnosticStages(err))
		}
	}
	t.Logf("actual_stock_selected_continuity=true dwell_seconds=50 same_original_review=true forward_checks=%d retained_checks=%d snapshot_unchanged=true selection_cancel=test_reader_only restored_intent_refuses=true closed_refuses=true cleanup_grant=false app_apply=false", forwardChecks, retainedChecks)
}

func nativeSelectedContinuityIntent(selection Selection) (Selection, error) {
	if selection.Revision == 0 || selection.Revision == ^uint64(0) || selection.PolicyRevision == 0 || selection.PolicyRevision == ^uint64(0) || len(selection.SegmentIDs) != 1 || selection.HomeSegmentID != "" || len(selection.GuestSegmentIDs) != 0 || selection.SelectedDevices == nil || len(selection.SelectedDevices.DeviceIDs) != 1 {
		return Selection{}, ErrUnknown
	}
	canonical, err := canonicalSelection(selection)
	if err != nil || slices.Contains(canonical.SelectedDevices.ExcludedDeviceIDs, canonical.SelectedDevices.DeviceIDs[0]) {
		return Selection{}, ErrUnknown
	}
	return canonical, nil
}

// Input refusal must precede any provider/socket acquisition. The one-device
// fixture here is ONLY intent validation, never an observed native fact.
func TestNativeSelectedContinuityIntentRefusesMissingOrNegativeInput(t *testing.T) {
	valid := selectedTestSelection()
	if _, err := nativeSelectedContinuityIntent(valid); err != nil {
		t.Fatal("bounded selected intent refused")
	}
	for name, change := range map[string]func(*Selection){
		"nil-projection":     func(s *Selection) { s.SelectedDevices = nil },
		"negative-only":      func(s *Selection) { s.SelectedDevices.DeviceIDs = nil },
		"missing-segment":    func(s *Selection) { s.SegmentIDs = nil },
		"multiple-segments":  func(s *Selection) { s.SegmentIDs = append(s.SegmentIDs, "Bridge1") },
		"missing-revision":   func(s *Selection) { s.Revision = 0 },
		"missing-policy":     func(s *Selection) { s.PolicyRevision = 0 },
		"revision-overflow":  func(s *Selection) { s.Revision = ^uint64(0) },
		"malformed-positive": func(s *Selection) { s.SelectedDevices.DeviceIDs[0] = "unknown" },
		"malformed-negative": func(s *Selection) { s.SelectedDevices.ExcludedDeviceIDs[0] = "unknown" },
		"excluded-positive":  func(s *Selection) { s.SelectedDevices.ExcludedDeviceIDs = slices.Clone(s.SelectedDevices.DeviceIDs) },
	} {
		t.Run(name, func(t *testing.T) {
			selection := cloneSnapshot(Snapshot{Selection: valid}).Selection
			change(&selection)
			if _, err := nativeSelectedContinuityIntent(selection); !errors.Is(err, ErrUnknown) {
				t.Fatal("unsupported selected intent admitted")
			}
		})
	}
}
