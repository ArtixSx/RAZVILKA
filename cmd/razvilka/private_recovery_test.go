package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestPrivateRecoveryMainChild(t *testing.T) {
	if os.Getenv("RAZVILKA_BOOT_CHILD") != "1" {
		return
	}
	base, mode := os.Getenv("RAZVILKA_BOOT_BASE"), os.Getenv("RAZVILKA_BOOT_MODE")
	flag.CommandLine = flag.NewFlagSet("razvilka", flag.ExitOnError)
	os.Args = []string{"razvilka"}
	// Every mutable destination is confined to the fixture even if a future
	// regression accidentally crosses the early recovery boundary.
	for _, name := range []string{"config", "catalog", "sources", "cache", "stage", "backups", "token-file", "credentials-file", "custom-services", "community-catalog", "warp-state", "cloudflare-state", "smart-route-state", "dataplane-state", "devices", "metrics-history", "strategy-lab-state", "audit-log", "dns-state", "node-state", "z2k-root"} {
		os.Args = append(os.Args, "-"+name, filepath.Join(base, name))
	}
	os.Args = append(os.Args, "-listen", "127.0.0.1:0")
	if mode != "server" {
		os.Args = append(os.Args, "-"+mode)
	}
	main()
}

func runPrivateRecoveryChild(t *testing.T, base, mode string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPrivateRecoveryMainChild$")
	cmd.Env = append(os.Environ(), "RAZVILKA_BOOT_CHILD=1", "RAZVILKA_BOOT_BASE="+base, "RAZVILKA_BOOT_MODE="+mode)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("startup gate did not exit promptly")
	}
	return string(output), err
}

func TestMainRecoveryGatePrecedesConfigCredentialsAndStores(t *testing.T) {
	for _, mode := range []string{"server", "migrate-config"} {
		for _, fault := range []string{"corrupt-journal", "running-instance"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				base := t.TempDir()
				journalRoot := filepath.Join(base, "private-restore")
				journalPath := filepath.Join(journalRoot, "restore.private.json")
				privateMarker := []byte(`{"private":"must-not-appear-in-logs"`)
				if fault == "corrupt-journal" {
					if err := os.Mkdir(journalRoot, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(journalPath, privateMarker, 0o600); err != nil {
						t.Fatal(err)
					}
				} else {
					guard, _, err := preparePrivateRecovery(filepath.Join(base, "config"), filepath.Join(base, "custom-services"), filepath.Join(base, "devices"), filepath.Join(base, "stage"), filepath.Join(base, "cloudflare-state"))
					if err != nil {
						t.Fatal(err)
					}
					defer guard.Close()
					if err := guard.StartRuntime(); err != nil {
						t.Fatal(err)
					}
				}
				output, err := runPrivateRecoveryChild(t, base, mode)
				if err == nil || !strings.Contains(output, "private draft recovery gate:") {
					t.Fatalf("startup not stopped at recovery gate: %v %s", err, output)
				}
				if strings.Contains(output, "must-not-appear-in-logs") || strings.Contains(output, base) {
					t.Fatal("private startup information leaked")
				}
				entries, err := os.ReadDir(base)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 1 || entries[0].Name() != "private-restore" {
					t.Fatal("startup created settings or credentials before recovery")
				}
				if fault == "corrupt-journal" {
					after, err := os.ReadFile(journalPath)
					if err != nil || !bytes.Equal(after, privateMarker) {
						t.Fatal("bad journal replaced")
					}
				}
			})
		}
	}
}

func TestReadOnlyCheckDoesNotAcquireOrRepairJournal(t *testing.T) {
	base := t.TempDir()
	for name, source := range map[string]string{"config": "config.example.json", "catalog": "service-catalog.json", "sources": "sources.json", "community-catalog": "community-catalog.json"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "configs", source))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(base, "private-restore"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "private-restore", "restore.private.json")
	if err := os.WriteFile(path, []byte("not-a-journal"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := runPrivateRecoveryChild(t, base, "check")
	if err != nil || !strings.Contains(output, `"ok": true`) {
		t.Fatal("read-only preflight was changed", err, output)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "not-a-journal" {
		t.Fatal("read-only check changed journal")
	}
	if _, err := os.Stat(filepath.Join(base, "private-restore", ".restore.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only check created lease marker")
	}
}

func TestPrivateRecoveryMaintenanceSettlesJournalWithoutLoadingStores(t *testing.T) {
	base := t.TempDir()
	output, err := runPrivateRecoveryChild(t, base, "recover-private-restore")
	if err != nil || !strings.Contains(output, `"ok":true`) || !strings.Contains(output, `"outcome":"clean"`) {
		t.Fatalf("maintenance recovery failed: %v %s", err, output)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name() != "private-restore" || entries[1].Name() != "private-restore-nodes-v1" {
		t.Fatalf("maintenance recovery loaded or created application stores: %v", entries)
	}
}

func TestPrivateRecoveryMaintenanceFailsClosedOnCorruptJournal(t *testing.T) {
	base := t.TempDir()
	journalRoot := filepath.Join(base, "private-restore")
	if err := os.Mkdir(journalRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(journalRoot, "restore.private.json")
	marker := []byte(`{"private":"do-not-replace"`)
	if err := os.WriteFile(journalPath, marker, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := runPrivateRecoveryChild(t, base, "recover-private-restore")
	if err == nil || !strings.Contains(output, "private draft recovery gate:") || strings.Contains(output, base) {
		t.Fatalf("maintenance recovery did not fail safely: %v %s", err, output)
	}
	after, readErr := os.ReadFile(journalPath)
	if readErr != nil || !bytes.Equal(after, marker) {
		t.Fatal("maintenance recovery replaced corrupt journal")
	}
}

func TestCleanGateDoesNotLoadOptionalProviderOrDrafts(t *testing.T) {
	base := t.TempDir()
	providerRoot := filepath.Join(base, "cloudflare-private")
	if err := os.Mkdir(providerRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	// Invalid optional contents belong to the provider's own loader, not clean
	// startup recovery. No archive currently refers to this target.
	path := filepath.Join(providerRoot, "accounts.private.json")
	if err := os.WriteFile(path, []byte("invalid-provider"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, out, err := preparePrivateRecovery(filepath.Join(base, "config"), filepath.Join(base, "custom"), filepath.Join(base, "devices"), filepath.Join(base, "stage"), "")
	if err != nil || out != restorejournal.Clean {
		t.Fatal(out, err)
	}
	defer c.Close()
	for _, name := range []string{"config", "custom", "devices", "stage"} {
		if _, err := os.Stat(filepath.Join(base, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("clean gate loaded a store", name)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "invalid-provider" {
		t.Fatal("optional provider was changed")
	}
}
