package privaterestore

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// The child writes REAL config/catalog/device/draft/provider adapters. Only the
// interruption checkpoints are injected; recovery is the production Open gate.
func TestCoordinatorCrashChild(t *testing.T) {
	if os.Getenv("RAZVILKA_COORD_CHILD") != "1" {
		return
	}
	base, point := os.Getenv("RAZVILKA_COORD_BASE"), os.Getenv("RAZVILKA_COORD_POINT")
	checkpoint := point
	online := strings.HasPrefix(point, "online/")
	point = strings.TrimPrefix(point, "online/")
	pause := func(name string) {
		if name == point {
			fmt.Println("checkpoint:" + checkpoint)
			_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
			os.Exit(91)
		}
	}
	c, _, err := Open(context.Background(), testLayout(base))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	writes := map[string]int{}
	c.beforeWrite = func(id string) error {
		pause("prepared")
		if point == "rollback" && id == "provider_cloudflare" {
			return errors.New("synthetic final target failure")
		}
		return nil
	}
	c.afterWrite = func(id string) {
		writes[id]++
		pause(id)
		if writes[id] == 2 && id == draftID("sing-box", "main") {
			pause("rollback")
		}
	}
	var out restorejournal.Outcome
	if online {
		stores := liveStores(t, testLayout(base))
		if err := c.StartRuntime(); err != nil {
			t.Fatal(err)
		}
		c.beforeHandover = func() error { pause("handover"); return nil }
		out, err = c.RestoreOnline(context.Background(), testPayload(t), map[string]bool{"youtube": true}, stores)
	} else {
		out, err = c.RestoreOffline(context.Background(), testPayload(t), map[string]bool{"youtube": true})
	}
	if err == nil && out == restorejournal.Applied {
		pause("complete")
	}
	t.Fatalf("checkpoint not reached: %s %v", out, err)
}

func killCoordinatorAt(t *testing.T, layout Layout, point string, whileRunning func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCoordinatorCrashChild$")
	cmd.Env = append(os.Environ(), "RAZVILKA_COORD_CHILD=1", "RAZVILKA_COORD_BASE="+filepath.Dir(layout.Config), "RAZVILKA_COORD_POINT="+point)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "checkpoint:"+point {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child exited before checkpoint", point)
		}
	case <-ctx.Done():
		t.Fatal("checkpoint timed out", point)
	}
	if whileRunning != nil {
		whileRunning()
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("child was not killed")
	}
}

func requireWriterExclusion(t *testing.T, layout Layout) {
	t.Helper()
	snapshot := imagesOnDisk(t, layout)
	s, err := config.Load(layout.Config)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateService("youtube", config.ServiceState{Route: "direct"}); err == nil {
		t.Fatal("ordinary config writer bypassed lease")
	}
	d, err := devices.Load(layout.Devices)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.MergeMetadata([]devices.Device{{ID: "test-device", Name: "Racing"}}); err == nil {
		t.Fatal("ordinary device writer bypassed lease")
	}
	m := engineconfig.New(layout.StageRoot, filepath.Join(filepath.Dir(layout.Config), "unused-backup"))
	if _, err := m.Stage("usque", "main", `{"racing":true}`); err == nil {
		t.Fatal("ordinary draft writer bypassed lease")
	}
	// These typed sessions use the same leases as ordinary registry/import writes.
	if target, err := customservices.OpenRestoreTarget(layout.CustomServices); err == nil {
		target.Close()
		t.Fatal("catalog lease not held")
	}
	if target, err := cloudflareprovider.OpenRestoreTarget(layout.ProviderRoot); err == nil {
		target.Close()
		t.Fatal("provider import lease not held")
	}
	requireImages(t, layout, snapshot)
}

func TestCombinedProcessCrashRecoversBeforeStoreLoad(t *testing.T) {
	for _, point := range []string{"prepared", "config", "custom_services", "devices", "draft_nfqws2_user-list", "draft_sing-box_main", "draft_usque_main", "provider_cloudflare", "rollback", "complete"} {
		t.Run(point, func(t *testing.T) {
			layout := seedLayout(t, t.TempDir())
			want := imagesOnDisk(t, layout)
			killCoordinatorAt(t, layout, point, func() {
				second, _, err := Open(context.Background(), layout)
				if second != nil {
					second.Close()
				}
				if !errors.Is(err, restorejournal.ErrBusy) {
					t.Fatal("second server was not fenced", err)
				}
				if point != "complete" {
					requireWriterExclusion(t, layout)
				} else {
					want = imagesOnDisk(t, layout)
					cfg, _, err := config.InspectBytes(want["config"].Data)
					if err != nil || cfg.Services["youtube"].Route != "usque" || !want["provider_cloudflare"].Exists {
						t.Fatal("completed state missing")
					}
				}
			})
			c, out, err := Open(context.Background(), layout)
			if err != nil {
				t.Fatal(out, err)
			}
			defer c.Close()
			if point != "complete" && out != restorejournal.RolledBack || point == "complete" && out != restorejournal.Clean {
				t.Fatal("unexpected recovery decision", out)
			}
			requireImages(t, layout, want)
			if len(c.acquired) != 0 {
				t.Fatal("recovery leaked target leases")
			}
			if err := c.StartRuntime(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOnlineProcessCrashRecoversBeforeStoreLoad(t *testing.T) {
	for _, point := range []string{"prepared", "config", "custom_services", "devices", "draft_nfqws2_user-list", "draft_sing-box_main", "draft_usque_main", "provider_cloudflare", "rollback", "handover", "complete"} {
		t.Run(point, func(t *testing.T) {
			layout := seedLayout(t, t.TempDir())
			want := imagesOnDisk(t, layout)
			killCoordinatorAt(t, layout, "online/"+point, func() {
				if point != "complete" {
					requireWriterExclusion(t, layout)
				}
				if point == "handover" || point == "complete" {
					want = imagesOnDisk(t, layout)
				}
			})
			c, out, err := Open(context.Background(), layout)
			if err != nil {
				t.Fatal(out, err)
			}
			defer c.Close()
			expected := restorejournal.RolledBack
			if point == "handover" {
				expected = restorejournal.Applied
			}
			if point == "complete" {
				expected = restorejournal.Clean
			}
			if out != expected {
				t.Fatal("wrong boot decision", out, expected)
			}
			requireImages(t, layout, want)
			stores := liveStores(t, layout)
			requireLiveCaches(t, layout, stores)
		})
	}
}

func TestStartupRefusesUnknownStateWithoutPartialRollback(t *testing.T) {
	for _, variant := range []string{"external-file", "changed-layout", "corrupt-journal", "unknown-lock"} {
		t.Run(variant, func(t *testing.T) {
			layout := seedLayout(t, t.TempDir())
			killCoordinatorAt(t, layout, "provider_cloudflare", nil)
			attempt := layout
			journalPath := filepath.Join(layout.JournalRoot, "restore.private.json")
			switch variant {
			case "external-file":
				data, err := os.ReadFile(layout.Config)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(layout.Config, append(data, ' '), 0o600); err != nil {
					t.Fatal(err)
				}
			case "changed-layout":
				attempt.StageRoot = filepath.Join(filepath.Dir(layout.Config), "different-stage")
			case "corrupt-journal":
				if err := os.WriteFile(journalPath, []byte(`{"secret":"do-not-log"`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "unknown-lock":
				if err := os.WriteFile(filepath.Join(layout.JournalRoot, ".restore.lock"), []byte("unknown-lock-format"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want := imagesOnDisk(t, layout)
			journal, err := os.ReadFile(journalPath)
			if err != nil {
				t.Fatal(err)
			}
			c, out, err := Open(context.Background(), attempt)
			if c != nil {
				c.Close()
			}
			if err == nil || out != restorejournal.Blocked {
				t.Fatal("unsafe startup accepted", out, err)
			}
			requireImages(t, layout, want)
			after, _ := os.ReadFile(journalPath)
			if !bytes.Equal(after, journal) {
				t.Fatal("blocked journal changed")
			}
			if variant == "changed-layout" {
				if _, err := os.Stat(attempt.StageRoot); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("alternate destination created")
				}
			}
		})
	}
}
