//go:build linux

package restorejournal

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"
)

// Paired actual owned-file I/O/SHA comparison only; generated fixture bytes
// are not native process/service/router evidence. Both algorithms hash the
// same two complete files and make the same original-FD MatchHeld callback.
func TestArtifactExpectedReadComparisonPairedWall(t *testing.T) {
	if os.Getenv("RAZVILKA_ARTIFACT_EXPECTED_TIMING") != "1" {
		t.Skip("explicit paired library measurement only")
	}
	previous := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previous)
	base := t.TempDir()
	poolDir, binDir := filepath.Join(base, "pool"), filepath.Join(base, "bin")
	for _, path := range []string{poolDir, binDir} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	const size = 64 << 20
	data := bytes.Repeat([]byte("actual bounded paired artifact hash fixture\n"), size/len("actual bounded paired artifact hash fixture\n"))
	image := artifactFixtureImage(t, poolDir, data)
	data = nil
	ref, err := artifactImageReference(image)
	if err != nil {
		t.Fatal(err)
	}
	target, err := OpenArtifactExecutableTarget(filepath.Join(binDir, "owned"), poolDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := target.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := target.CompareAndSwap(ctx, Image{}, image); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(filepath.Join(poolDir, ref.SHA256+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	read := func(c context.Context, actual Image, proof *ArtifactSourceComparison) error {
		if !equal(actual, image) {
			return ErrConflict
		}
		return proof.MatchHeld(c, held)
	}
	var before, after []time.Duration
	t.Logf("paired_artifact_environment bytes_each=%d complete_files_per_call=2 samples_each=12 GOMAXPROCS=2 cpu_count=%d reference=sequential_current_comparison optimized=parallel_expected_comparison claim=owned_file_library_only", ref.Size, runtime.NumCPU())
	t.Log("paired_artifact_csv,sample,algorithm,order,elapsed_ms")
	for i := 0; i < 12; i++ {
		for offset := 0; offset < 2; offset++ {
			optimized := (i+offset)%2 == 1
			started := time.Now()
			var err error
			name := "sequential"
			if optimized {
				name = "parallel"
				err = target.WithExpectedReadComparison(ctx, image, read)
			} else {
				err = target.WithReadComparison(ctx, read)
			}
			elapsed := time.Since(started)
			if err != nil {
				t.Fatal(name, err)
			}
			if optimized {
				after = append(after, elapsed)
			} else {
				before = append(before, elapsed)
			}
			t.Logf("paired_artifact_csv,%d,%s,%d,%.3f", i+1, name, offset+1, float64(elapsed)/float64(time.Millisecond))
		}
	}
	quantile := func(samples []time.Duration, percent int) time.Duration {
		copy := append([]time.Duration(nil), samples...)
		sort.Slice(copy, func(i, j int) bool { return copy[i] < copy[j] })
		return copy[(percent*len(copy)+99)/100-1]
	}
	for _, cohort := range []struct {
		name   string
		values []time.Duration
	}{{"sequential", before}, {"parallel", after}} {
		t.Log(fmt.Sprintf("paired_artifact_summary algorithm=%s N=12 quantile=nearest_rank p50_ms=%.3f p95_ms=%.3f", cohort.name, float64(quantile(cohort.values, 50))/float64(time.Millisecond), float64(quantile(cohort.values, 95))/float64(time.Millisecond)))
	}
}
