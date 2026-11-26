package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func bootRetirementMainArgs(base string) []string {
	args := []string{"-listen", "127.0.0.1:0"}
	// Confine every destination even if early-dispatch ordering regresses.
	for _, name := range []string{"config", "catalog", "sources", "cache", "stage", "backups", "token-file", "credentials-file", "custom-services", "community-catalog", "warp-state", "cloudflare-state", "smart-route-state", "dataplane-state", "devices", "metrics-history", "strategy-lab-state", "audit-log", "dns-state", "node-state", "z2k-root", "component-state", "component-bin", "component-init", "component-repo", "component-info", "self-update-installation", "self-update-file-state", "self-update-helper-state", "self-update-control-state"} {
		args = append(args, "-"+name, filepath.Join(base, name))
	}
	return args
}

func TestBootRetirementMainRejectsUnpairedAndMixedModesBeforeWrites(t *testing.T) {
	paired := []string{"-retire-rollback-after-boot-plan", "dp-1111111111111111", "-retire-rollback-after-boot-digest", strings.Repeat("a", 64)}
	for _, extra := range [][]string{paired[:2], paired[2:], append(append([]string{}, paired...), "-check"), append(append([]string{}, paired...), "-retry-rollback-plan", "dp-2222222222222222", "-retry-rollback-digest", strings.Repeat("b", 64))} {
		base := t.TempDir()
		output, err := selfUpdateMainSubprocess(t, append(bootRetirementMainArgs(base), extra...)...)
		if err == nil || !bytes.Contains(output, []byte("requires both")) && !bytes.Contains(output, []byte("mutually exclusive")) {
			t.Fatalf("offline mode was not rejected before bootstrap: %v %s", err, output)
		}
		entries, err := os.ReadDir(base)
		if err != nil || len(entries) != 0 {
			t.Fatal("invalid offline flags caused filesystem writes", entries, err)
		}
	}
}

func TestBootRetirementMainRefusesWithoutCreatingOrdinaryStores(t *testing.T) {
	for _, mode := range []string{"missing-config", "missing-history", "running-instance"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			cfgPath := filepath.Join(base, "config")
			var original []byte
			if mode != "missing-config" {
				if _, err := config.Load(cfgPath); err != nil {
					t.Fatal(err)
				}
				var err error
				original, err = os.ReadFile(cfgPath)
				if err != nil {
					t.Fatal(err)
				}
			}
			stage := filepath.Join(base, "stage", "sing-box")
			if err := os.MkdirAll(stage, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(stage, 0755); err != nil {
				t.Fatal(err)
			}
			if mode == "running-instance" {
				guard, _, err := preparePrivateRecovery(cfgPath, filepath.Join(base, "custom-services"), filepath.Join(base, "devices"), filepath.Join(base, "stage"), filepath.Join(base, "cloudflare-state"))
				if err != nil {
					t.Fatal(err)
				}
				defer guard.Close()
				if err := guard.StartRuntime(); err != nil {
					t.Fatal(err)
				}
			}
			args := append(bootRetirementMainArgs(base), "-retire-rollback-after-boot-plan", "dp-1111111111111111", "-retire-rollback-after-boot-digest", strings.Repeat("a", 64))
			output, err := selfUpdateMainSubprocess(t, args...)
			if err == nil || bytes.Contains(output, []byte("flag provided but not defined")) {
				t.Fatalf("offline refusal did not run: %v %s", err, output)
			}
			if mode == "missing-history" && !bytes.Contains(output, []byte("offline post-reboot retirement")) || mode == "running-instance" && !bytes.Contains(output, []byte("private draft recovery gate")) {
				t.Fatalf("wrong refusal boundary: %s", output)
			}
			for _, name := range []string{"token-file", "credentials-file", "admin.sessions.json", "catalog", "sources", "cache", "custom-services", "devices", "smart-route-state", "node-state", "audit-log", "dns-state"} {
				if _, err := os.Lstat(filepath.Join(base, name)); !os.IsNotExist(err) {
					t.Fatal("offline refusal created unrelated state", name, err)
				}
			}
			after, err := os.ReadFile(cfgPath)
			if mode == "missing-config" {
				if !os.IsNotExist(err) {
					t.Fatal("missing recovery settings replaced by defaults", err)
				}
			} else if err != nil || !bytes.Equal(after, original) {
				t.Fatal("offline refusal modified settings", err)
			}
			if info, err := os.Stat(stage); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0755 {
				t.Fatal("offline refusal normalized an unrelated staging directory", err)
			}
		})
	}
}
