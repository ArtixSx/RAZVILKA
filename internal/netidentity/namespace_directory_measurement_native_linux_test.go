//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package netidentity

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// Only a namespace enumeration leaf is measured. Complete Provider observations
// and their authority are neither replaced nor timed by this experiment.
func namespaceDirectoryNativeLeaf(ctx context.Context, fixed bool) (result namespaceDirectoryResult, err error) {
	fd, err := syscall.Open("/proc/self/ns", dirFlags, 0)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, syscall.Close(fd)) }()
	position, err := syscall.Seek(fd, 0, 1)
	if err != nil || position != 0 {
		return result, errors.New("fresh namespace directory position")
	}
	if fixed {
		result.names, result.unknown, result.complete, result.valid = readNamespaceDirectoryFD(ctx, fd)
	} else {
		result = namespaceDirectoryRun(ctx, func(buf []byte) (int, error) { return syscall.ReadDirent(fd, buf) }, true)
	}
	return result, nil
}

func TestNamespaceDirectoryFDNativeContracts(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	want, err := namespaceDirectoryNativeLeaf(ctx, false)
	if err != nil || !want.complete || !want.valid || len(want.names) == 0 {
		t.Fatal("original complete namespace enumeration", err, want)
	}
	got, err := namespaceDirectoryNativeLeaf(ctx, true)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("fixed FD parity", err, got, want)
	}
	// A subsequent independently opened directory must not overwrite prior names.
	frozen := append([]string(nil), got.names...)
	for range 4 {
		if _, err := namespaceDirectoryNativeLeaf(ctx, true); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(got.names, frozen) {
		t.Fatal("returned names share scratch")
	}
	for _, original := range []bool{true, false} {
		var r namespaceDirectoryResult
		if original {
			r = namespaceDirectoryRun(ctx, func(buf []byte) (int, error) { return syscall.ReadDirent(-1, buf) }, true)
		} else {
			r.names, r.unknown, r.complete, r.valid = readNamespaceDirectoryFD(ctx, -1)
		}
		if r.complete || r.valid || len(r.names) != 0 {
			t.Fatal("invalid FD accepted")
		}
	}
	fd, err := syscall.Open("/proc/self/ns", dirFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := syscall.Close(fd); err != nil {
			t.Error(err)
		}
	}()
	cancelled, revoke := context.WithCancel(ctx)
	revoke()
	if _, _, complete, valid := readNamespaceDirectoryFD(cancelled, fd); complete || valid {
		t.Fatal("cancelled read")
	}
	if position, err := syscall.Seek(fd, 0, 1); err != nil || position != 0 {
		t.Fatal("cancelled reader consumed directory", position, err)
	}
	// A regular file provides an actual syscall refusal; it is never parsed as dirents.
	f, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, _, complete, valid := readNamespaceDirectoryFD(ctx, int(f.Fd())); complete || valid {
		t.Fatal("regular FD accepted")
	}
}

func namespaceDirectoryCPU(who int) (int64, error) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(who, &usage); err != nil {
		return 0, err
	}
	return usage.Utime.Nano() + usage.Stime.Nano(), nil
}

func TestNamespaceDirectoryFDNativePaired(t *testing.T) {
	if os.Getenv("RAZVILKA_NAMESPACE_DIRECTORY_MEASURE") != "1" {
		t.Skip("explicit native namespace measurement")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	tid := syscall.Gettid()
	want, err := namespaceDirectoryNativeLeaf(ctx, false)
	if err != nil || !want.complete || !want.valid {
		t.Fatal("original namespace baseline", err)
	}
	for _, fixed := range []bool{false, true} {
		got, err := namespaceDirectoryNativeLeaf(ctx, fixed)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("warmup mismatch", err)
		}
	}
	const iterations = 512
	for pair := 0; pair < 8; pair++ {
		order := []bool{false, true}
		if pair%2 != 0 {
			order = []bool{true, false}
		}
		for position, fixed := range order {
			variant := "original_callback"
			if fixed {
				variant = "fixed_fd"
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			threadBefore, err := namespaceDirectoryCPU(-1)
			if err != nil {
				t.Fatal(err)
			}
			processBefore, err := namespaceDirectoryCPU(syscall.RUSAGE_SELF)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			for range iterations {
				got, err := namespaceDirectoryNativeLeaf(ctx, fixed)
				if err != nil || !reflect.DeepEqual(got, want) || ctx.Err() != nil {
					t.Fatal("fresh full leaf mismatch", err, ctx.Err())
				}
			}
			wall := time.Since(start)
			threadAfter, err := namespaceDirectoryCPU(-1)
			if err != nil {
				t.Fatal(err)
			}
			processAfter, err := namespaceDirectoryCPU(syscall.RUSAGE_SELF)
			if err != nil {
				t.Fatal(err)
			}
			runtime.ReadMemStats(&after)
			if threadAfter < threadBefore || processAfter < processBefore || after.TotalAlloc < before.TotalAlloc || after.Mallocs < before.Mallocs || syscall.Gettid() != tid {
				t.Fatal("measurement generation/thread drift")
			}
			row := struct {
				Pair           int    `json:"pair"`
				Position       int    `json:"position"`
				Variant        string `json:"variant"`
				Calls          int    `json:"calls"`
				WallNS         int64  `json:"wall_ns"`
				ThreadCPUNS    int64  `json:"thread_cpu_ns"`
				ProcessCPUNS   int64  `json:"process_cpu_ns"`
				AllocatedBytes uint64 `json:"allocated_bytes"`
				Allocations    uint64 `json:"allocations"`
				Names          int    `json:"names"`
			}{pair, position, variant, iterations, wall.Nanoseconds(), threadAfter - threadBefore, processAfter - processBefore, after.TotalAlloc - before.TotalAlloc, after.Mallocs - before.Mallocs, len(want.names)}
			data, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("namespace-directory-paired %s", data)
		}
	}
	closing, err := namespaceDirectoryNativeLeaf(ctx, false)
	if err != nil || !reflect.DeepEqual(closing, want) {
		t.Fatal("closing namespace changed", err)
	}
}

func BenchmarkNamespaceDirectoryFDReader(b *testing.B) {
	for _, fixed := range []bool{false, true} {
		name := "original_callback"
		if fixed {
			name = "fixed_fd"
		}
		b.Run(name, func(b *testing.B) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ctx, cancel := context.WithTimeout(b.Context(), 60*time.Second)
			defer cancel()
			want, err := namespaceDirectoryNativeLeaf(ctx, false)
			if err != nil || !want.complete || !want.valid {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				got, err := namespaceDirectoryNativeLeaf(ctx, fixed)
				if err != nil || !reflect.DeepEqual(got, want) {
					b.Fatal("parity", err)
				}
			}
		})
	}
}
