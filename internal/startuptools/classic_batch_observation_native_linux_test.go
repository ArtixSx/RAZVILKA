//go:build linux && amd64 && razvilka_native_fixture

package startuptools

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestStaticVersionFactNativeClassicBatchBookends(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	l := staticFactNativeLease(t, ctx)
	var original [2][][]byte
	err := l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(observed context.Context) error {
		for sample := range 12 {
			before := NativeFixtureVersionMetadataCount(l)
			started := time.Now()
			result, err := l.ReadBoundedClassicTables(observed, l.identity, l.digest, l.profile.aliases, 1<<20, [2][]string{{"mangle"}, {"mangle"}})
			elapsed := time.Since(started)
			if err != nil {
				return err
			}
			// Each of the TWO real children keeps an opening and closing
			// complete graph. The nonempty batch adds no extra metadata pair.
			if count := NativeFixtureVersionMetadataCount(l) - before; count != 4 {
				t.Fatal("actual child metadata bookends changed", count)
			}
			for family := range result {
				if len(result[family]) != 1 || len(result[family][0]) == 0 {
					t.Fatal("incomplete actual IPv4/IPv6 table image")
				}
				if sample > 0 && !bytes.Equal(result[family][0], original[family][0]) {
					t.Fatal("same actual table image changed")
				}
			}
			original = result
			t.Logf("classic_batch_actual sample=%d children=2 metadata=4 elapsed_ms=%.3f", sample, float64(elapsed.Microseconds())/1000)
		}
		return nil
	})
	if err != nil {
		t.Fatal("actual original batch or full-SHA closing", nativeStages(err))
	}
}
