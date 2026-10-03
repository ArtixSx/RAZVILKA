//go:build linux

package awgprofile

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// An opt-in read-only check of the actual loaded runtime. A missing or
// unverifiable module fails this explicitly requested test; it is not skipped
// or installed. Incompatible receipts below are copies, never loaded modules.
func TestAWGNativeCompatibilityReceipt(t *testing.T) {
	if os.Getenv("RAZVILKA_AWG_NATIVE") != "1" {
		t.Skip("requires explicitly assigned Linux AWG host: RAZVILKA_AWG_NATIVE=1")
	}
	tool := os.Getenv("RAZVILKA_AWG_NATIVE_TOOL")
	if tool == "" {
		tool = "awg"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	before := readLoadedRuntime(readVersion)
	c := DetectTool(ctx, tool)
	// Public inventory must survive a failed gate too; no profiles/keys are read.
	data, _ := json.Marshal(c)
	t.Log("public read-only inventory", string(data))
	if issues := CheckRuntime(Preview{MinimumMajor: 3, MinimumMinor: 1}, c); len(issues) != 0 {
		t.Fatal("actual AWG 3.1 compatibility not established", issues)
	}
	if _, err := VerifyTool(ctx, c, tool); err != nil {
		t.Fatal(err)
	}
	if before != readLoadedRuntime(readVersion) {
		t.Fatal("loaded runtime changed during read-only test")
	}
	for _, change := range []string{"source", "kernel", "forced", "CLI"} {
		bad := c
		switch change {
		case "source":
			bad.LoadedSourceVersion = ""
		case "kernel":
			bad.Kernel += "-wrong"
		case "forced":
			bad.KernelTaint = "2"
		case "CLI":
			bad.ToolVersion = "wireguard-tools v3.1.0"
		}
		if len(CheckRuntime(Preview{MinimumMajor: 3, MinimumMinor: 1}, bad)) == 0 {
			t.Fatal("incompatible copied receipt accepted", change)
		}
	}
}
