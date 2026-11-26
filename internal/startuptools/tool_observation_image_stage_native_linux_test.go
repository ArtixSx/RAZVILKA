//go:build linux && amd64 && razvilka_native_fixture

package startuptools

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type toolObservationImageStageTiming struct {
	Sample            int   `json:"sample"`
	Images            int   `json:"images"`
	GraphBytes        int64 `json:"graph_bytes"`
	RetainedBytes     int   `json:"retained_bytes"`
	ColdAllocation    bool  `json:"cold_allocation"`
	OriginalOpeningNS int64 `json:"original_opening_ns"`
	OriginalClosingNS int64 `json:"original_closing_ns"`
	OriginalPairNS    int64 `json:"original_pair_ns"`
	BorrowNS          int64 `json:"borrow_ns"`
	OpeningNS         int64 `json:"opening_ns"`
	ClosingNS         int64 `json:"closing_ns"`
	ReleaseNS         int64 `json:"release_ns"`
	ImagePairNS       int64 `json:"image_pair_ns"`
}

// Measures the original two source-boundary methods on an actual protected
// acquired Lease. There is no callback, command, publication or fake scope.
// This empty byte pair isolates source/clear cost; it is NOT an observation
// lifecycle benchmark, process memory delta or end-to-end route timing.
func TestToolObservationImageStageMeasurement(t *testing.T) {
	if os.Getenv("RAZVILKA_TOOL_IMAGE_MEASURE") != "1" {
		t.Skip("explicit actual protected tool graph stage measurement only")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	l := versionNamesActualLease(t, ctx)
	if err := l.retain(ctx); err != nil {
		t.Fatal(err)
	}
	defer l.retained.Done()
	var slot toolObservationImageScratch
	for sample := 0; sample < 3; sample++ {
		row := toolObservationImageStageTiming{Sample: sample, Images: len(l.review.images), GraphBytes: l.review.bytes, ColdAllocation: slot.data == nil}
		pairStart := time.Now()
		start := time.Now()
		err := l.observationBytes(ctx, l.identity, l.digest)
		row.OriginalOpeningNS = time.Since(start).Nanoseconds()
		if err != nil {
			t.Fatal("actual original opening", nativeStages(err))
		}
		start = time.Now()
		err = l.observationBytes(ctx, l.identity, l.digest)
		row.OriginalClosingNS = time.Since(start).Nanoseconds()
		row.OriginalPairNS = time.Since(pairStart).Nanoseconds()
		if err != nil {
			t.Fatal("actual original closing", nativeStages(err))
		}
		func() {
			pairStart = time.Now()
			start = time.Now()
			image, err := borrowToolObservationImage(ctx, l.review, &slot)
			row.BorrowNS = time.Since(start).Nanoseconds()
			if err != nil || image == nil {
				t.Fatal("actual protected graph image unavailable; no measurement", l.review.bytes, err)
			}
			defer image.release()
			row.RetainedBytes = len(slot.data)
			start = time.Now()
			err = l.observationBytesWithImage(ctx, l.identity, l.digest, image)
			row.OpeningNS = time.Since(start).Nanoseconds()
			if err != nil || image.phase != 1 {
				t.Fatal("actual image opening", nativeStages(err))
			}
			start = time.Now()
			err = l.observationBytesWithImage(ctx, l.identity, l.digest, image)
			row.ClosingNS = time.Since(start).Nanoseconds()
			if err != nil || image.phase != 2 {
				t.Fatal("actual image closing", nativeStages(err))
			}
			start = time.Now()
			image.release()
			row.ReleaseNS = time.Since(start).Nanoseconds()
			row.ImagePairNS = time.Since(pairStart).Nanoseconds()
			if slot.busy.Load() || image.scratch != nil || image.entries != nil || image.ctx != nil {
				t.Fatal("original release retained storage/observation")
			}
		}()
		for _, b := range slot.data {
			if b != 0 {
				t.Fatal("original release did not clear complete backing")
			}
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("actual_tool_observation_image_stages %s", raw)
	}
	t.Log("same-process empty actual source pairs; release includes complete clear; cold allocation is not cold page cache; no route readiness or router RSS claim")
}
