package commandrun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--diagnostic-helper" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "sleep":
		time.Sleep(3 * time.Second)
	case "large":
		fmt.Print(strings.Repeat("x", 65536))
	case "pipes":
		child := exec.Command(os.Args[0], "-test.run=^TestDiagnosticHelper$", "--", "--diagnostic-helper", "sleep")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		_ = child.Process.Release()
	default:
		fmt.Print("healthy")
	}
	os.Exit(0)
}

func TestOutputBoundsTimeBytesAndInheritedPipes(t *testing.T) {
	// Race-instrumented helper executables otherwise sleep for one second on
	// exit, which is unrelated to the command/pipes being measured here.
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode string
		want error
	}{
		{"sleep", context.DeadlineExceeded},
		{"large", ErrOutputLimit},
		{"pipes", exec.ErrWaitDelay},
		{"ok", nil},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			started := time.Now()
			data, err := Output(context.Background(), time.Second, 32, binary, "-test.run=^TestDiagnosticHelper$", "--", "--diagnostic-helper", tc.mode)
			if !errors.Is(err, tc.want) || len(data) > 32 {
				t.Fatalf("bytes=%d error=%v, want %v", len(data), err, tc.want)
			}
			if time.Since(started) > 2500*time.Millisecond {
				t.Fatal("diagnostic exceeded its hard bound")
			}
		})
	}
}

func TestOutputCancelledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Output(ctx, time.Second, 32, "does-not-exist"); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
