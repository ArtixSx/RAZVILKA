package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestMihomoParentRetirementMainRefusesBeforeOrdinaryStartup(t *testing.T) {
	pair := []string{"-retire-mihomo-probe-after-parent-plan", "dp-check-" + strings.Repeat("a", 32), "-retire-mihomo-probe-after-parent-digest", strings.Repeat("b", 64)}
	for _, extra := range [][]string{pair[:2], pair[2:], append(append([]string{}, pair...), "-check"), append(append([]string{}, pair...), "-retire-mihomo-probe-after-boot-plan", "dp-check-"+strings.Repeat("c", 32), "-retire-mihomo-probe-after-boot-digest", strings.Repeat("d", 64)), pair} {
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
		if err == nil || bytes.Contains(output, []byte("flag provided but not defined")) {
			t.Fatal("original offline refusal did not execute", err, string(output))
		}
		entries, err := os.ReadDir(base)
		if err != nil || len(entries) != 0 {
			t.Fatal("refusal created unrelated state", entries, err)
		}
	}
}
