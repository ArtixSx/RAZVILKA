//go:build linux && (amd64 || arm64)

package components

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"time"
)

// Full original verifier, file/metadata/EOF/hash reads and its release/clear.
// Payload contents and installation authority are the explicit MODEL; member
// sizes match the reviewed ARM64 graph. No binary runs or route is proved.
// Holding the retained slot makes the original sync.Pool fallback execute;
// holding/releasing that independent borrower is outside timed verifier work.
func TestManagedRuntimeScratchFullImagePairs(t *testing.T) {
	if os.Getenv("RAZVILKA_RUNTIME_SCRATCH_MEASURE") != "1" {
		t.Skip("explicit full-image scratch measurement")
	}
	manifest, err := ReviewedManagedNFQWSManifest("arm64")
	if err != nil {
		t.Fatal(err)
	}
	manifest.Flavor = "scratch-full-image-size-model"
	var entries []bundleFixtureEntry
	var payloadBytes int64
	for i := range manifest.Members {
		member := &manifest.Members[i]
		data := bytes.Repeat([]byte{byte(0x31 + i)}, int(member.RawSize))
		payloadBytes += member.RawSize
		member.RawSHA256 = digest(data)
		if member.Gzip {
			data = bundleFixtureGzip(t, data)
		}
		member.Size, member.SHA256 = int64(len(data)), digest(data)
		entries = append(entries, bundleFixtureEntry{member.Path, data, tar.TypeReg})
	}
	input := bundleFixtureContainer(t, entries)
	manifest.ParentAssetSize, manifest.ParentSHA256 = int64(len(input)), digest(input)
	m := bundleFixtureManager(t, input)
	receipt, err := m.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority())
	if err != nil {
		t.Fatal(err)
	}
	call := func() {
		got, err := m.verifyManagedNFQWSRuntimeImage(context.Background(), receipt.GenerationPath, receipt.ManifestSHA256)
		if err != nil {
			t.Fatal(err)
		}
		gotHash, err := got.Digest()
		if err != nil || gotHash != receipt.ManifestSHA256 {
			t.Fatal("actual original verifier differs", err)
		}
	}
	withHolder := func(hold bool, use func()) {
		if hold {
			holder := acquireManagedRuntimePayloadScratch()
			defer releaseManagedRuntimePayloadScratch(holder)
			if holder != &managedRuntimePayloadRetained.scratch {
				t.Fatal("pool comparison did not hold original slot")
			}
		}
		use()
	}
	call()                 // Warm the retained capacity, separately from the measured series.
	withHolder(true, call) // Warm original pool fallback independently.
	for _, regime := range []string{"steady", "after-two-GC"} {
		for sample, mode := range []string{"pool", "retained", "retained", "pool", "pool", "retained", "retained", "pool"} {
			withHolder(mode == "pool", func() {
				if regime == "after-two-GC" {
					runtime.GC()
					runtime.GC()
				}
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				started := time.Now()
				call()
				elapsed := time.Since(started)
				runtime.ReadMemStats(&after)
				row := struct {
					Regime               string `json:"regime"`
					Mode                 string `json:"mode"`
					Sample               int    `json:"sample"`
					WallNS               int64  `json:"wall_ns"`
					AllocBytes           uint64 `json:"alloc_bytes"`
					AllocObjects         uint64 `json:"alloc_objects"`
					PayloadBytes         int64  `json:"payload_bytes"`
					RetainedMaximumBytes int    `json:"retained_maximum_bytes"`
				}{regime, mode, sample, elapsed.Nanoseconds(), after.TotalAlloc - before.TotalAlloc, after.Mallocs - before.Mallocs, payloadBytes, 6*((1<<20)+1) + (32 << 10)}
				wire, err := json.Marshal(row)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("nfq_runtime_scratch_pair %s", wire)
			})
		}
	}
	// Checking ALL capacity bytes is outside the timed verifier; its own
	// release already performed the mandatory clearing inside each sample.
	for _, data := range managedRuntimePayloadRetained.scratch.members {
		if !bytes.Equal(data[:cap(data)], make([]byte, cap(data))) {
			t.Fatal("original verifier retained payload data")
		}
	}
	if managedRuntimePayloadRetained.busy.Load() {
		t.Fatal("original verifier retained its borrow")
	}
}
