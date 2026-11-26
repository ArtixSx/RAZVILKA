//go:build linux && amd64 && razvilka_native_fixture

package dataplane

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// A diagnostic of the actual byte pair, not the process/network observer or
// an alternative implementation. Production opening, closing and clearing
// run unchanged; no detector suppression or reduced read boundary is used.
type mihomoColdSelfImageStageTiming struct {
	Sample            int   `json:"sample"`
	ImageBytes        int64 `json:"image_bytes"`
	RetainedBytes     int   `json:"retained_bytes"`
	ColdStorage       bool  `json:"cold_storage"`
	OriginalOpeningNS int64 `json:"original_opening_ns"`
	OriginalClosingNS int64 `json:"original_closing_ns"`
	OriginalPairNS    int64 `json:"original_pair_ns"`
	BorrowNS          int64 `json:"borrow_ns"`
	OpeningNS         int64 `json:"opening_ns"`
	ClosingNS         int64 `json:"closing_ns"`
	ReleaseNS         int64 `json:"release_ns"`
	ImagePairNS       int64 `json:"image_pair_ns"`
}

func TestMihomoColdSelfImageStageMeasurement(t *testing.T) {
	if os.Getenv("RAZVILKA_COLD_SELF_IMAGE_MEASURE") != "1" {
		t.Skip("explicit actual binary byte-pair measurement only")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	var scratch xrayDomainTCPImageScratch
	for sample := 0; sample < 3; sample++ {
		row := mihomoColdSelfImageStageTiming{Sample: sample, ColdStorage: scratch.data == nil}
		pairStart := time.Now()
		start := time.Now()
		first, a, err := mihomoColdFileHash(ctx, "/proc/self/exe")
		row.OriginalOpeningNS = time.Since(start).Nanoseconds()
		if err != nil {
			t.Fatal("original opening", err)
		}
		start = time.Now()
		second, b, err := mihomoColdFileHash(ctx, "/proc/self/exe")
		row.OriginalClosingNS = time.Since(start).Nanoseconds()
		row.OriginalPairNS = time.Since(pairStart).Nanoseconds()
		if err != nil || first != second || !os.SameFile(a, b) || a.Size() != b.Size() {
			t.Fatal("original pair", err)
		}
		row.ImageBytes = a.Size()
		func() {
			pairStart = time.Now()
			start = time.Now()
			image, err := borrowMihomoColdSelfImage(ctx, "/proc/self/exe", &scratch)
			row.BorrowNS = time.Since(start).Nanoseconds()
			if err != nil || image == nil {
				t.Fatal("actual binary image unavailable; no measurement", row.ImageBytes, err)
			}
			defer image.release() // Original idempotent cleanup also covers Fatal/panic.
			row.RetainedBytes = len(scratch.data)
			start = time.Now()
			opening, opened, err := image.read(ctx)
			row.OpeningNS = time.Since(start).Nanoseconds()
			if err != nil || opening != first || !os.SameFile(a, opened) || a.Size() != opened.Size() {
				t.Fatal("image opening differs from actual original", err)
			}
			start = time.Now()
			closing, closed, err := image.read(ctx)
			row.ClosingNS = time.Since(start).Nanoseconds()
			if err != nil || closing != opening || !os.SameFile(opened, closed) || opened.Size() != closed.Size() {
				t.Fatal("image closing differs from actual original", err)
			}
			start = time.Now()
			image.release()
			row.ReleaseNS = time.Since(start).Nanoseconds()
			row.ImagePairNS = time.Since(pairStart).Nanoseconds()
			if scratch.busy.Load() || !image.lease.closed.Load() {
				t.Fatal("actual release retained storage owner")
			}
		}()
		// Outside measured stages, verify the original clearing contract over
		// ALL retained storage, without allocating another image for comparison.
		for _, b := range scratch.data {
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
		t.Logf("actual_mihomo_cold_self_image_stages %s", raw)
	}
	t.Log("three same-process original pairs and unchanged image pairs; release includes full clear; diagnostic only, no route readiness or router RSS claim")
}
