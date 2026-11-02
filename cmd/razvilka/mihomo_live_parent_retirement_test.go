package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestMihomoLiveParentRetirementFlagsAreDistinctPairedAndExclusive(t *testing.T) {
	preserveMihomoLiveRetirementFlags(t)
	f := flag.NewFlagSet("cold-live", flag.ContinueOnError)
	registerBootRetirementFlags(f)
	if err := f.Parse([]string{"-retire-mihomo-live-after-parent-plan", "dp-1111111111111111", "-retire-mihomo-live-after-parent-digest", strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	if !mihomoLiveParentRetirementCLIRequested() || !bootRetirementCLIRequested() || bootRetirementCLIFlagError() != nil || mihomoBootRetirementCLIRequested() || mihomoParentRetirementCLIRequested() {
		t.Fatal("distinct live mode not retained")
	}
	for _, pointer := range []*string{retireRollbackBootPlan, retireMihomoBootPlan, retireMihomoParentPlan, retireMihomoLiveBootPlan} {
		*pointer = "foreign-mode"
		if bootRetirementCLIFlagError() == nil {
			t.Fatal("mixed retirement modes admitted")
		}
		*pointer = ""
	}
	*retireMihomoLiveParentDigest = ""
	if bootRetirementCLIFlagError() == nil {
		t.Fatal("unpaired live mode admitted")
	}
}

func TestMihomoLiveParentRetirementContextRefusalPreservesException(t *testing.T) {
	preserveMihomoLiveRetirementFlags(t)
	*retireMihomoLiveParentPlan, *retireMihomoLiveParentDigest = "dp-1111111111111111", strings.Repeat("a", 64)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := runMihomoLiveParentRetirementCLI(ctx, offlineNFQWS2StopPaths{}, "")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, dataplane.ErrMihomoLiveRetirement) || out.PlanID != "" {
		t.Fatal("cancellation or fence identity lost", out, err)
	}
	var diagnostic *mihomoLiveBootCLIError
	if !errors.As(err, &diagnostic) || diagnostic.stage != "context" {
		t.Fatal("unsafe context stage", err)
	}
	if _, err := runMihomoLiveParentRetirementCLI(context.Background(), offlineNFQWS2StopPaths{}, ""); !errors.Is(err, dataplane.ErrMihomoLiveRetirement) {
		t.Fatal("unbounded context admitted", err)
	}
}

func TestMihomoLiveParentRetirementMainRefusesBeforeOrdinaryStartup(t *testing.T) {
	paired := []string{"-retire-mihomo-live-after-parent-plan", "dp-1111111111111111", "-retire-mihomo-live-after-parent-digest", strings.Repeat("a", 64)}
	for _, extra := range [][]string{paired[:2], paired[2:], append(append([]string{}, paired...), "-check"), append(append([]string{}, paired...), "-retire-mihomo-probe-after-boot-plan", "dp-check-"+strings.Repeat("b", 32), "-retire-mihomo-probe-after-boot-digest", strings.Repeat("c", 64)), paired} {
		base := t.TempDir()
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		args := append([]string{"-test.run=^TestMihomoBootRetirementSubprocess$", "--"}, bootRetirementMainArgs(base)...)
		command := exec.CommandContext(ctx, exe, append(args, extra...)...)
		command.Env = append(os.Environ(), "RAZVILKA_MIHOMO_RETIREMENT_TEST=1", "RAZVILKA_MIHOMO_RETIREMENT_TEST_ROOT="+t.TempDir())
		output, err := command.CombinedOutput()
		cancel()
		if err == nil || bytes.Contains(output, []byte("flag provided but not defined")) || bytes.Contains(output, []byte(`"state":"rolled-back"`)) {
			t.Fatalf("explicit real main refusal missing: %v %s", err, output)
		}
		entries, err := os.ReadDir(base)
		if err != nil || len(entries) != 0 {
			t.Fatal("offline refusal created ordinary application state", entries, err)
		}
	}
}
