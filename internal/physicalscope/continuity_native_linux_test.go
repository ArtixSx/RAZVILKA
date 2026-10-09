//go:build linux

package physicalscope

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Root-only read-only continuity diagnostic. Explicit opt-in:
// RAZVILKA_PHYSICAL_SCOPE_CONTINUITY_NATIVE=1
// RAZVILKA_PHYSICAL_SCOPE_NATIVE=stock-nc1812
// RAZVILKA_PHYSICAL_SCOPE_CONTINUITY_SELECTION_FILE=<absolute private JSON>
// The file contains only the original configured Selection intent, including
// its actual revisions and SegmentIDs. It contains no NI, physical facts or
// permission. Native NDM roles/links/neighbors and identity are freshly proved
// by the production factories. No automatic Home or bridge choice is made.
// RAZVILKA_PHYSICAL_SCOPE_CONTINUITY_SECONDS optionally selects 1..300 seconds;
// default 180. Root owns ARM64 build/run/cleanup and the longer test timeout.
func TestPhysicalScopeNativeRetainedContinuity(t *testing.T) {
	if os.Getenv("RAZVILKA_PHYSICAL_SCOPE_CONTINUITY_NATIVE") != "1" {
		t.Skip("Root-only opt-in read-only continuity diagnostic")
	}
	if runtime.GOARCH != "arm64" || os.Getenv("RAZVILKA_PHYSICAL_SCOPE_NATIVE") != "stock-nc1812" {
		t.Skip("continuity requires actual reviewed stock NC1812 on Linux ARM64")
	}
	window := 180 * time.Second
	if text := os.Getenv("RAZVILKA_PHYSICAL_SCOPE_CONTINUITY_SECONDS"); text != "" {
		seconds, err := strconv.ParseUint(text, 10, 16)
		if err != nil || seconds < 1 || seconds > 300 || strconv.FormatUint(seconds, 10) != text {
			t.Fatal("continuity duration input refused")
		}
		window = time.Duration(seconds) * time.Second
	}
	// Finite aggregate context includes original acquisition and the final
	// Verify. Production provider/observer/leaf bounds are never overridden.
	ctx, cancel := context.WithTimeout(context.Background(), window+30*time.Second)
	defer cancel()
	if deadline, ok := t.Deadline(); ok {
		bounded, finish := context.WithDeadline(ctx, deadline)
		defer finish()
		ctx = bounded
	}
	selection, err := continuityNativePrivateSelection(os.Getenv("RAZVILKA_PHYSICAL_SCOPE_CONTINUITY_SELECTION_FILE"))
	if err != nil {
		t.Fatal("continuity private Selection input refused")
	}
	read := func(c context.Context) (Selection, error) {
		// Frozen Root-chosen intent only. No selection change, refresh or
		// snapshot adoption can renew this original physical Review.
		chosen := selection
		chosen.SegmentIDs = slices.Clone(selection.SegmentIDs)
		return chosen, c.Err()
	}
	provider, err := netidentity.NewReviewedStockNC1812Provider(ctx)
	if err != nil {
		t.Fatalf("continuity provider refused: %v", DiagnosticStages(err))
	}
	observer := NewReviewedStockNC1812(provider, read)
	review, err := observer.Observe(ctx)
	if err != nil {
		t.Fatalf("continuity observe refused: %v", DiagnosticStages(err))
	}
	defer func() {
		if err := review.Close(); err != nil {
			t.Errorf("continuity close refused: %v", DiagnosticStages(err))
		}
	}()
	until := time.Now().Add(window)
	for {
		if err := observer.Verify(ctx, review); err != nil {
			// First refusal ends the test; never retry or replace the Review.
			// Format only closed labels, never an error or physical snapshot.
			t.Fatalf("continuity verify refused: %v", DiagnosticStages(err))
		}
		if !time.Now().Before(until) {
			return
		}
		delay := min(time.Second, time.Until(until))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatalf("continuity context refused: %v", DiagnosticStages(ctx.Err()))
		case <-timer.C:
		}
	}
}

func continuityNativePrivateSelection(path string) (Selection, error) {
	if !filepath.IsAbs(path) {
		return Selection{}, ErrUnknown
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return Selection{}, ErrUnknown
	}
	f, err := os.Open(path)
	if err != nil {
		return Selection{}, ErrUnknown
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !actual.Mode().IsRegular() || !os.SameFile(info, actual) {
		return Selection{}, ErrUnknown
	}
	const limit = 16 << 10
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(data) > limit {
		return Selection{}, ErrUnknown
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var selection Selection
	if decoder.Decode(&selection) != nil || len(selection.SegmentIDs) == 0 || selection.HomeSegmentID != "" || len(selection.GuestSegmentIDs) != 0 {
		return Selection{}, ErrUnknown
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return Selection{}, ErrUnknown
	}
	return canonicalSelection(selection)
}
