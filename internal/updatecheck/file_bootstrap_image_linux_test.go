//go:build linux

package updatecheck

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"
	"unsafe"
)

func TestBootstrapImageUsesOriginalHelperDigestAndRevokes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	data := ordinaryImageBytes(ordinaryImageChunk + 13)
	review := fileReview{OldExecutableSHA256: digestBytes([]byte("different old193 source")), Bootstrap: &fileBootstrapBinding{HelperSHA256: digestBytes(data)}}
	if image, err := bootstrapExecutableImage(ctx, fileReview{OldExecutableSHA256: review.OldExecutableSHA256}); image != nil || err == nil {
		t.Fatal("ordinary/source image gained bootstrap use")
	}
	image, err := bootstrapExecutableImage(ctx, review)
	if err != nil {
		t.Fatal(err)
	}
	defer image.clear()
	if ordinaryImageRetainLimit+int(unsafe.Sizeof(*image)) > 64<<20 {
		t.Fatal("bootstrap role image exceeds 64 MiB bound")
	}
	first := &ordinaryCountedImageReader{source: bytes.NewReader(data)}
	if got, err := image.verify(first, int64(len(data))); err != nil || got != review.Bootstrap.HelperSHA256 || first.bytes != len(data) {
		t.Fatal("original helper digest/full image lost", err)
	}
	// A later full occurrence with a changed byte cannot inherit the first SHA.
	changed := bytes.Clone(data)
	changed[len(changed)-1] ^= 1
	next := &ordinaryCountedImageReader{source: bytes.NewReader(changed)}
	owned := image.image
	if _, err := image.verify(next, int64(len(changed))); err == nil || next.bytes != len(changed) || !image.closed || !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("changed closing image accepted or retained")
	}
	if _, err := image.verify(bytes.NewReader(data), int64(len(data))); err == nil {
		t.Fatal("poisoned image revived")
	}
	fresh, err := bootstrapExecutableImage(ctx, review)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.clear()
	cancel()
	if _, err := fresh.controllerAt(os.Getpid()); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled original role context revived", err)
	}
}

// Actual same /proc/exe, parent/argv/birth/FD observations, not a granted role.
// Every per-call image has a fresh SHA and is cleared before the next sample.
// Positive installer authority is covered only by the public native workflow.
func TestBootstrapImageActualGroupParityAndMeasurement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	expected, err := bootstrapControllerAt(ctx, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	review := fileReview{OldExecutableSHA256: digestBytes([]byte("old193")), Bootstrap: &fileBootstrapBinding{HelperSHA256: expected.Process.ExecutableSHA256}}
	info, err := os.Stat("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	for sample := 0; sample < 3; sample++ {
		var before, after time.Duration
		var retainedBytes int
		var streamingFallback bool
		for pass := 0; pass < 2; pass++ {
			optimized := (sample+pass)%2 == 1
			read := func() (bootstrapControllerFact, error) { return bootstrapControllerAt(ctx, os.Getpid()) }
			var image *ordinaryExecutableImage
			start := time.Now()
			if optimized {
				image, err = bootstrapExecutableImage(ctx, review)
				if err != nil {
					t.Fatal(err)
				}
				read = func() (bootstrapControllerFact, error) { return image.controllerAt(os.Getpid()) }
			}
			for occurrence := 0; occurrence < 8; occurrence++ {
				actual, err := read()
				if err != nil || !reflect.DeepEqual(actual, expected) {
					if image != nil {
						image.clear()
					}
					t.Fatal("actual complete process occurrence changed", err)
				}
			}
			if image != nil {
				retainedBytes = len(image.image) + int(unsafe.Sizeof(*image))
				streamingFallback = image.image == nil
				image.clear()
			}
			elapsed := time.Since(start)
			if optimized {
				after = elapsed
			} else {
				before = elapsed
			}
		}
		t.Logf("actual_bootstrap_role_image sample=%d controller_occurrences=8 full_exe_reads=16 image_bytes=%d retained_bytes=%d streaming_fallback=%t before=%s after=%s no_role_grant=true", sample, info.Size(), retainedBytes, streamingFallback, before, after)
	}
}
