package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Integration fixture only: production startup/general archive are not yet
// wired to these targets. Each checkpoint uses the actual file/store adapters.
type registryCheckpoint struct {
	restorejournal.Target
	before func()
	after  func()
	fail   bool
}

func (t registryCheckpoint) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	if t.before != nil {
		t.before()
	}
	if t.fail {
		return errors.New("synthetic registry write failure")
	}
	if err := t.Target.CompareAndSwap(ctx, before, after); err != nil {
		return err
	}
	if t.after != nil {
		t.after()
	}
	return nil
}
func registryScope(bindings ...string) string {
	h := sha256.New()
	h.Write([]byte("registry-recovery-test-v1"))
	for _, b := range bindings {
		h.Write([]byte{0})
		h.Write([]byte(b))
	}
	return hex.EncodeToString(h.Sum(nil))
}
func TestRegistryRecoveryChild(t *testing.T) {
	if os.Getenv("RAZVILKA_REGISTRY_CHILD") != "1" {
		return
	}
	base, point := os.Getenv("RAZVILKA_REGISTRY_BASE"), os.Getenv("RAZVILKA_REGISTRY_POINT")
	ctx := context.Background()
	pause := func(name string) {
		if point != name {
			return
		}
		fmt.Println("checkpoint:" + name)
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		os.Exit(91)
	}
	cfg, err := config.Load(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cat, err := customservices.Load(filepath.Join(base, "custom.json"))
	if err != nil {
		t.Fatal(err)
	}
	dev, err := devices.Load(filepath.Join(base, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	cs, err := cfg.BeginRestore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	ks, err := cat.BeginRestore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()
	ds, err := dev.BeginRestore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ds.Close()
	ci, err := cs.DraftImage(ctx, map[string]config.ServiceState{"telegram": {Enabled: true, Route: "usque"}})
	if err != nil {
		t.Fatal(err)
	}
	ki, err := ks.MergeImage(ctx, []catalog.Service{{ID: "custom-import", Name: "Imported", Domains: []string{"import.example"}}}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	di, err := ds.MergeImage(ctx, []devices.Device{{ID: "test-device", Name: "Imported"}})
	if err != nil {
		t.Fatal(err)
	}
	catWrites := 0
	targets := map[string]restorejournal.Target{
		"a_config": registryCheckpoint{Target: cs, before: func() { pause("prepared") }, after: func() { pause("config") }},
		"b_catalog": registryCheckpoint{Target: ks, after: func() {
			catWrites++
			if catWrites == 1 {
				pause("catalog")
			} else {
				pause("rollback")
			}
		}},
		"c_devices": registryCheckpoint{Target: ds, after: func() { pause("devices") }, fail: point == "rollback"},
	}
	j, err := restorejournal.Open(filepath.Join(base, "journal"), registryScope(cs.Binding(), ks.Binding(), ds.Binding()), targets)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	out, err := j.Execute(ctx, map[string]restorejournal.Image{"a_config": ci, "b_catalog": ki, "c_devices": di})
	if out == restorejournal.Applied && err == nil {
		pause("complete")
	}
	t.Fatalf("checkpoint missed: %s %v", out, err)
}

func killRegistryChild(t *testing.T, base, point string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRegistryRecoveryChild$")
	cmd.Env = append(os.Environ(), "RAZVILKA_REGISTRY_CHILD=1", "RAZVILKA_REGISTRY_BASE="+base, "RAZVILKA_REGISTRY_POINT="+point)
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
			t.Fatal("child exited before checkpoint")
		}
	case <-ctx.Done():
		t.Fatal("child checkpoint timed out")
	}
	// Fresh caches may read partial atomic files. Their writes still cannot pass
	// the file leases held by the other process, for ALL three registries.
	c, err := config.Load(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetSafeMode(false); !errors.Is(err, restorejournal.ErrBusy) {
		t.Fatal("config lease bypass")
	}
	k, err := customservices.Load(filepath.Join(base, "custom.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Create(catalog.Service{Name: "Other", Domains: []string{"other.example"}}, nil); !errors.Is(err, restorejournal.ErrBusy) {
		t.Fatal("catalog lease bypass")
	}
	d, err := devices.Load(filepath.Join(base, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Update("test-device", "Other", ""); !errors.Is(err, restorejournal.ErrBusy) {
		t.Fatal("device lease bypass")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("child not killed")
	}
}

func seedRecoveryRegistries(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	cfg, err := config.Load(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	cat, err := customservices.Load(filepath.Join(base, "custom.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cat.Create(catalog.Service{Name: "Before", Domains: []string{"before.example"}}, nil); err != nil {
		t.Fatal(err)
	}
	dev, err := devices.Load(filepath.Join(base, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.MergeMetadata([]devices.Device{{ID: "test-device", Name: "Before", IPs: []string{"192.168.1.5"}}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "journal"), 0o700); err != nil {
		t.Fatal(err)
	}
	return base
}
func readRegistryFiles(t *testing.T, base string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, name := range []string{"config.json", "custom.json", "devices.json"} {
		data, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			t.Fatal(err)
		}
		out[name] = data
	}
	return out
}
func recoverRegistries(t *testing.T, base string) (restorejournal.Outcome, error) {
	t.Helper()
	// These targets open BEFORE caches or discovery/background tasks.
	cfg, err := config.OpenRestoreTarget(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	cat, err := customservices.OpenRestoreTarget(filepath.Join(base, "custom.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer cat.Close()
	dev, err := devices.OpenRestoreTarget(filepath.Join(base, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	j, err := restorejournal.Open(filepath.Join(base, "journal"), registryScope(cfg.Binding(), cat.Binding(), dev.Binding()), map[string]restorejournal.Target{"a_config": cfg, "b_catalog": cat, "c_devices": dev})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	return j.Recover(context.Background())
}
func TestRegistryRecoveryBeforeCacheLoad(t *testing.T) {
	for _, point := range []string{"prepared", "config", "catalog", "devices", "rollback", "complete"} {
		t.Run(point, func(t *testing.T) {
			base := seedRecoveryRegistries(t)
			before := readRegistryFiles(t, base)
			killRegistryChild(t, base, point)
			out, err := recoverRegistries(t, base)
			expected := restorejournal.RolledBack
			if point == "complete" {
				expected = restorejournal.Clean
			}
			if err != nil || out != expected {
				t.Fatalf("%s %v", out, err)
			}
			if point != "complete" {
				for name, data := range readRegistryFiles(t, base) {
					if !bytes.Equal(data, before[name]) {
						t.Fatalf("%s not restored exactly", name)
					}
				}
			}
			cfg, err := config.Load(filepath.Join(base, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Get().Services["telegram"].Enabled != (point == "complete") || !cfg.Get().SafeMode || !cfg.Get().AppliedServices["youtube"].Enabled {
				t.Fatal("config/live fields wrong")
			}
			cat, err := customservices.Load(filepath.Join(base, "custom.json"))
			if err != nil {
				t.Fatal(err)
			}
			if cat.Has("custom-import") != (point == "complete") || !cat.Has("custom-before") {
				t.Fatal("catalog cache wrong")
			}
			dev, err := devices.Load(filepath.Join(base, "devices.json"))
			if err != nil {
				t.Fatal(err)
			}
			known := dev.Known()
			if len(known) != 1 || known[0].Discovered || (known[0].Name == "Imported") != (point == "complete") {
				t.Fatal("device cache wrong")
			}
			if _, err := dev.Update("test-device", "Next", ""); err != nil {
				t.Fatal("device writer unavailable")
			}
			if _, err := cat.Create(catalog.Service{Name: "Next", Domains: []string{"next.example"}}, nil); err != nil {
				t.Fatal("catalog writer unavailable")
			}
		})
	}
}
func TestRegistryRecoveryRefusesUnknownExternalState(t *testing.T) {
	base := seedRecoveryRegistries(t)
	killRegistryChild(t, base, "catalog")
	// Simulate a noncooperating external writer AFTER crash. It must not cause
	// an automatic undo of the other targets before the conflict is noticed.
	dev, err := devices.Load(filepath.Join(base, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dev.Update("test-device", "External", ""); err != nil {
		t.Fatal(err)
	}
	before := readRegistryFiles(t, base)
	out, err := recoverRegistries(t, base)
	if out != restorejournal.Blocked || err == nil {
		t.Fatal("external change ignored")
	}
	for name, data := range readRegistryFiles(t, base) {
		if !bytes.Equal(data, before[name]) {
			t.Fatalf("conflict changed %s", name)
		}
	}
}
