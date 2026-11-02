//go:build linux && razvilka_native_fixture

package app

import (
	"context"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type managedProbeNativeToolMeasurements struct {
	calls atomic.Uint64
	nanos atomic.Int64
}

// Delegate EVERY actual check to its original lease. This records cost only;
// it neither caches a result nor replaces a failed/closed owner with success.
func (m *managedProbeNativeToolMeasurements) wrap(original func(context.Context, netidentity.Identity) error) func(context.Context, netidentity.Identity) error {
	return func(ctx context.Context, identity netidentity.Identity) error {
		start := time.Now()
		m.calls.Add(1)
		defer func() { m.nanos.Add(time.Since(start).Nanoseconds()) }()
		return original(ctx, identity)
	}
}

func managedProbeNativeCPUProfile(t *testing.T, _ string) func() {
	t.Helper()
	work := os.Getenv("RAZVILKA_MANAGED_PROBE_FIXTURE_WORK")
	info, err := os.Lstat(work)
	if err != nil || filepath.Clean(work) != work || filepath.Dir(work) != "/tmp" || !strings.HasPrefix(filepath.Base(work), "razvilka-managed-probe.") || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		t.Fatal("actual private CI profile directory required", err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		t.Fatal("foreign CI profile directory refused")
	}
	path := filepath.Join(work, filepath.Base(t.Name())+".pprof")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			pprof.StopCPUProfile()
			if err := f.Close(); err != nil {
				t.Log("native CPU profile close", err)
				return
			}
			// The parent analyzes this AFTER leaving the private /opt mount,
			// which intentionally hides the host Go compiler/toolchain.
			t.Log("native measured CPU profile saved", filepath.Base(path))
			memory, err := os.OpenFile(path+".alloc", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Error("native allocation profile create", err)
				return
			}
			writeErr := pprof.Lookup("allocs").WriteTo(memory, 0)
			closeErr := memory.Close()
			if writeErr != nil || closeErr != nil {
				t.Error("native allocation profile write/close", writeErr, closeErr)
			}
		})
	}
}
