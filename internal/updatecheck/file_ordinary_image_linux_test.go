//go:build linux

package updatecheck

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"
)

// ROOT actual dependency opt-in: real /proc/exe/argv/birth observations only.
// This is no installer role, inactive runtime or future-update acceptance.
func TestOrdinaryImageNativeActualFactAndRepeatedRead(t *testing.T) {
	if os.Getenv("RAZVILKA_ORDINARY_IMAGE_NATIVE") != "1" {
		t.Skip("ROOT actual Linux dependency opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	before, err := bootstrapControllerAt(ctx, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	r, err := newOrdinaryExecutableImage(ctx, before.Process.ExecutableSHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer r.clear()
	started := time.Now()
	for i := 0; i < 10; i++ { // Twenty actual full /proc/exe reads.
		actual, err := r.controllerAt(os.Getpid())
		if err != nil || !reflect.DeepEqual(actual, before) {
			t.Fatal("original actual process/FD/argv/birth observations changed", i, err)
		}
	}
	optimized := time.Since(started)
	started = time.Now()
	for i := 0; i < 10; i++ {
		actual, err := bootstrapControllerAt(ctx, os.Getpid())
		if err != nil || !reflect.DeepEqual(actual, before) {
			t.Fatal("original actual baseline observation changed", i, err)
		}
	}
	// Timings are observations, never an assertion that the 2s DNS budget or
	// the complete genuine installer observation has been accepted.
	mode := "full-byte-comparison"
	if r.image == nil {
		mode = "streaming-fallback"
	}
	t.Logf("actual image dependency: full_occurrences=20 mode=%s retained_bytes=%d new_reader=%s original_streaming_sha=%s", mode, len(r.image), optimized, time.Since(started))
}
