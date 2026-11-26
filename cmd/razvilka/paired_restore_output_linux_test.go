//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestNativePairedRestoreOutputCopyLimit(t *testing.T) {
	for _, size := range []int64{0, 64 << 10, (64 << 10) + 1} {
		var out nativePairedRestoreOutput
		// LimitReader hides the source WriterTo and exercises destination ReadFrom.
		n, err := io.Copy(&out, io.LimitReader(strings.NewReader(strings.Repeat("x", int(size))), size))
		if size <= 64<<10 {
			if err != nil || n != size || int64(out.Len()) != size {
				t.Fatal("bounded copy changed", n, err, out.Len())
			}
		} else if !errors.Is(err, io.ErrShortBuffer) || n != 64<<10 || out.Len() != 64<<10 {
			t.Fatal("promoted reader bypassed output cap", n, err, out.Len())
		}
	}
	// Preserve original WriterTo preference and its single large Write boundary.
	var out nativePairedRestoreOutput
	n, err := io.Copy(&out, strings.NewReader(strings.Repeat("x", (64<<10)+1)))
	if n != 0 || !errors.Is(err, io.ErrShortBuffer) || out.Len() != 0 {
		t.Fatal("source fast-path changed", n, err, out.Len())
	}
}

func TestNativePairedRestoreOutputChild(t *testing.T) {
	stream := os.Getenv("RAZVILKA_TEST_PAIRED_OUTPUT_CHILD")
	if stream != "stdout" && stream != "stderr" {
		return
	}
	file := os.Stdout
	if stream == "stderr" {
		file = os.Stderr
	}
	_, _ = file.Write([]byte(strings.Repeat("x", (64<<10)+1)))
	os.Exit(0)
}

func TestNativePairedRestoreOutputActualPipesRemainBounded(t *testing.T) {
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, program, "-test.run=^TestNativePairedRestoreOutputChild$")
			command.Env = append(os.Environ(), "RAZVILKA_TEST_PAIRED_OUTPUT_CHILD="+stream)
			stdout, stderr := &nativePairedRestoreOutput{}, &nativePairedRestoreOutput{}
			command.Stdout, command.Stderr = stdout, stderr
			command.WaitDelay = 100 * time.Millisecond
			err := command.Run()
			selected, other := stdout, stderr
			if stream == "stderr" {
				selected, other = stderr, stdout
			}
			if err == nil || ctx.Err() != nil || command.ProcessState == nil || selected.Len() == 0 || selected.Len() > 64<<10 || other.Len() != 0 {
				t.Fatal("actual pipe cap or original join lost", err, ctx.Err(), stdout.Len(), stderr.Len())
			}
			if command.Wait() == nil {
				t.Fatal("actual child was not already joined")
			}
		})
	}
}
