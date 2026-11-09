//go:build linux && amd64 && razvilka_native_fixture

package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestMihomoSameBootNativeOutputCopy(t *testing.T) {
	for _, size := range []int{0, 32768, 32769} {
		var out sameBootNativeOutput
		n, err := io.Copy(&out, io.LimitReader(strings.NewReader(strings.Repeat("x", size)), int64(size)))
		if size <= 32768 {
			if err != nil || n != int64(size) || out.Len() != size || out.overflow {
				t.Fatal("bounded output changed", n, err, out.Len())
			}
		} else if err == nil || !out.overflow || n > 32768 || out.Len() > 32768 {
			t.Fatal("copy bypassed original shared cap", n, err, out.Len())
		}
	}
}

func TestMihomoSameBootNativeOutputChild(t *testing.T) {
	mode := os.Getenv("RAZVILKA_SAME_BOOT_OUTPUT_CHILD")
	switch mode {
	case "stdout":
		_, _ = os.Stdout.Write([]byte(strings.Repeat("x", 32769)))
	case "stderr":
		_, _ = os.Stderr.Write([]byte(strings.Repeat("x", 32769)))
	case "combined":
		_, _ = os.Stdout.Write([]byte(strings.Repeat("x", 20000)))
		_, _ = os.Stderr.Write([]byte(strings.Repeat("x", 20000)))
	default:
		return
	}
	os.Exit(0)
}

func TestMihomoSameBootNativeOutputActualPipes(t *testing.T) {
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"stdout", "stderr", "combined"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, program, "-test.run=^TestMihomoSameBootNativeOutputChild$")
			command.Env = append(os.Environ(), "RAZVILKA_SAME_BOOT_OUTPUT_CHILD="+mode)
			var output sameBootNativeOutput
			command.Stdout, command.Stderr = &output, &output
			command.WaitDelay = 100 * time.Millisecond
			err := command.Run()
			if err == nil || ctx.Err() != nil || command.ProcessState == nil || !output.overflow || output.Len() == 0 || output.Len() > 32768 {
				t.Fatal("actual shared pipe cap or original join lost", err, ctx.Err(), output.Len(), output.overflow)
			}
			if command.Wait() == nil {
				t.Fatal("actual helper was not already joined")
			}
		})
	}
}
