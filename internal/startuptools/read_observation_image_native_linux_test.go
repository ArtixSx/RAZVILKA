//go:build linux && amd64 && razvilka_native_fixture

package startuptools

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestToolObservationImageActualLease(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	l := versionNamesActualLease(t, ctx)
	for sample := 0; sample < 3; sample++ {
		start := time.Now()
		if err := l.observationBytes(ctx, l.identity, l.digest); err != nil {
			t.Fatal(nativeStages(err))
		}
		if err := l.observationBytes(ctx, l.identity, l.digest); err != nil {
			t.Fatal(nativeStages(err))
		}
		before := time.Since(start)
		start = time.Now()
		used := false
		var escaped context.Context
		err := l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(observed context.Context) error {
			escaped = observed
			used = toolObservationScratch.busy.Load()
			return l.WithReadOnlyToolObservation(observed, l.identity, l.digest, func(nested context.Context) error {
				if nested != observed {
					return errors.New("nested original context changed")
				}
				return l.readObservationCurrent(nested)
			})
		})
		after := time.Since(start)
		if err != nil {
			t.Fatal("actual outer/nested original read", nativeStages(err))
		}
		if l.readObservationCurrent(escaped) == nil {
			t.Fatal("escaped original read authority survived")
		}
		if toolObservationScratch.busy.Load() {
			t.Fatal("actual joined read retained private slot")
		}
		if l.review.bytes > toolObservationImageLimit && used {
			t.Fatal("oversize graph borrowed capped storage")
		}
		t.Logf("actual original tool graph sample=%d images=%d graph_bytes=%d image_used=%t fixed_slot_bytes=%d full_SHA_pair=%s scoped_pair=%s; isolated read cost, not route or router acceptance", sample, len(l.review.images), l.review.bytes, used, len(toolObservationScratch.data), before, after)
		if !used {
			t.Fatal("pinned actual graph did not exercise byte-image path; no image performance result")
		}
	}
}
