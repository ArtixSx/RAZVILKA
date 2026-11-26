//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAdmissionRejectsConcurrentOtherKernelThread(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	thread, starts := syscall.Gettid(), 0
	ctx := WithCommandAdmission(context.Background(), admissionFunc(func(_ context.Context, _ string, _ []string, _ string, begin func() error) error {
		done := make(chan error, 1)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			done <- begin()
		}()
		return <-done
	}))
	err := invokeAdmission(ctx, "/fixed/alias", nil, "digest", func() bool { return syscall.Gettid() == thread }, func() error { starts++; return nil })
	if !errors.Is(err, ErrUnknown) || starts != 0 {
		t.Fatal("other thread started command under caller namespace admission", err)
	}
}

// This is read-only even with native opt-in. Effects require CORE's actual
// original operation/control/review barrier in the integrated owner fixture.
func TestProductionStartupPolicyNative(t *testing.T) {
	mode := os.Getenv("RAZVILKA_STARTUP_TOOLS_NATIVE")
	if mode == "" {
		t.Skip("Root production startup tools native fixture opt-in disabled")
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	setup, setupCancel := context.WithTimeout(lifetime, operationTimeout)
	provider := nativeProvider(t, setup, mode)
	setupCancel()
	t.Setenv("LD_PRELOAD", "/unreviewed-startup-tools-preload.so")
	t.Setenv("LD_LIBRARY_PATH", "/unreviewed-startup-tools-libraries")
	t.Setenv("XTABLES_LIBDIR", "/unreviewed-startup-tools-extensions")
	var lease *Lease
	var err error
	started := time.Now()
	if mode == "stock-nc1812" {
		lease, err = AcquireReviewedStockNC1812Policy(lifetime, provider)
	} else {
		lease, err = AcquireUbuntuLegacyPolicy(lifetime, provider)
	}
	acquired := time.Since(started)
	if err != nil {
		t.Fatalf("production policy acquisition refused: acquisition-ms=%d stages=%s", acquired.Milliseconds(), nativeStages(err))
	}
	defer lease.Close()
	t.Logf("production policy acquisition passed: acquisition-ms=%d images=%d bytes=%d nodes=%d review=%s; no mutation grant", acquired.Milliseconds(), len(lease.review.images), lease.review.bytes, len(lease.review.nodes), lease.digest)
	tools, runner, err := lease.PolicyRuntimeTools()
	if err != nil {
		t.Fatal(err)
	}
	// No admission is needed for these exact, numeric inspection commands.
	for _, family := range []string{"-4", "-6"} {
		read, readCancel := context.WithTimeout(lifetime, operationTimeout)
		readStart := time.Now()
		data, err := runner.Run(read, tools.IP, family, "-N", "rule", "show")
		readElapsed, readContext := time.Since(readStart), nativeContextState(read)
		readCancel()
		if err != nil {
			t.Fatalf("actual policy IP read refused: acquisition-ms=%d read-ms=%d read-context=%s family=%s stages=%s", acquired.Milliseconds(), readElapsed.Milliseconds(), readContext, family, nativeStages(err))
		}
		t.Logf("numeric RPDB family=%s read-ms=%d read-context=%s bytes=%d rows=%d", family, readElapsed.Milliseconds(), readContext, len(data), strings.Count(string(data), "\n"))
	}
	// This command is never started: absence of CORE admission must refuse it.
	if data, err := runner.Run(lifetime, tools.IPTables, "-t", "mangle", "-N", "RZG_unissued_native"); !errors.Is(err, ErrUnknown) || len(data) != 0 {
		t.Fatal("unadmitted effect issued success", err)
	}
	t.Logf("production policy lease images=%d bytes=%d review=%s; no mutation grant", len(lease.review.images), lease.review.bytes, lease.digest)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lease.PolicyRuntimeTools(); err == nil {
		t.Fatal("closed lease issued policy tools")
	}
	if data, err := runner.Run(context.Background(), tools.IP, "-4", "-N", "rule", "show"); err == nil || len(data) != 0 {
		t.Fatal("saved policy runner survived Close")
	}
}
