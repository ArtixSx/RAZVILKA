package main

import (
	"bytes"
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMihomoBootRetirementSubprocess(t *testing.T) {
	if os.Getenv("RAZVILKA_MIHOMO_RETIREMENT_TEST") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet("razvilka", flag.ExitOnError)
	fixture := os.Getenv("RAZVILKA_MIHOMO_RETIREMENT_TEST_ROOT")
	os.Exit(mainWithSelfUpdateJournalRoots(selfUpdateJournalRoots{installation: filepath.Join(fixture, "installation"), helper: filepath.Join(fixture, "helper"), files: filepath.Join(fixture, "files")}))
}

func TestMihomoBootRetirementMainRefusesBeforeOrdinaryStartup(t *testing.T) {
	paired := []string{"-retire-mihomo-probe-after-boot-plan", "dp-check-" + strings.Repeat("a", 32), "-retire-mihomo-probe-after-boot-digest", strings.Repeat("b", 64)}
	for _, extra := range [][]string{paired[:2], paired[2:], append(append([]string{}, paired...), "-check"), append(append([]string{}, paired...), "-retire-rollback-after-boot-plan", "dp-1111111111111111", "-retire-rollback-after-boot-digest", strings.Repeat("c", 64)), paired} {
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
			t.Fatalf("offline refusal did not execute: %v %s", err, output)
		}
		entries, err := os.ReadDir(base)
		if err != nil || len(entries) != 0 {
			t.Fatal("offline refusal created unrelated state", entries, err)
		}
	}
}
