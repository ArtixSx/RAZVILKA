//go:build linux && razvilka_native_fixture

package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/pprof"
	"sync"
	"sync/atomic"
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

func managedProbeNativeCPUProfile(t *testing.T, root string) func() {
	t.Helper()
	path := filepath.Join(root, "native-probe-cpu.pprof")
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
			program, err := os.Executable()
			if err != nil {
				t.Log(err)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// Diagnostic only, AFTER actual Execute. The linked profile contains
			// function names/counts, no payload, credentials or owner recreation.
			cmd := exec.CommandContext(ctx, "go", "tool", "pprof", "-top", "-nodecount=20", program, path)
			cmd.WaitDelay = 100 * time.Millisecond
			output, err := cmd.CombinedOutput()
			if len(output) > 64<<10 {
				output = output[:64<<10]
			}
			t.Log("native measured CPU profile", err, "\n"+string(output))
		})
	}
}
