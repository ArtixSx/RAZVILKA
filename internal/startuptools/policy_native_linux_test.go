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
	if mode == "stock-nc1812" {
		lease, err = AcquireReviewedStockNC1812Policy(lifetime, provider)
	} else {
		lease, err = AcquireUbuntuLegacyPolicy(lifetime, provider)
	}
	if err != nil {
		t.Fatal("production policy acquisition refused: stages=", nativeStages(err))
	}
	defer lease.Close()
	tools, runner, err := lease.PolicyRuntimeTools()
	if err != nil {
		t.Fatal(err)
	}
	// No admission is needed for these exact, numeric inspection commands.
	for _, family := range []string{"-4", "-6"} {
		data, err := runner.Run(lifetime, tools.IP, family, "-N", "rule", "show")
		if err != nil {
			t.Fatal("actual policy IP read refused: stages=", nativeStages(err))
		}
		t.Logf("numeric RPDB family=%s bytes=%d rows=%d", family, len(data), strings.Count(string(data), "\n"))
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
