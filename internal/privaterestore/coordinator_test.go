package privaterestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func testLayout(base string) Layout {
	return Layout{Config: filepath.Join(base, "config.json"), CustomServices: filepath.Join(base, "custom.json"), Devices: filepath.Join(base, "devices.json"), StageRoot: filepath.Join(base, "stage"), ProviderRoot: filepath.Join(base, "provider"), JournalRoot: filepath.Join(base, "journal")}
}

func seedLayout(t *testing.T, base string) Layout {
	t.Helper()
	layout := testLayout(base)
	s, err := config.Load(layout.Config)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	cfg := s.Get()
	cfg.AppliedServices = map[string]config.ServiceState{"youtube": {Enabled: true, Route: "nfqws2"}}
	cfg.AppliedRevision = cfg.Revision
	cfg.SafeMode = false
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(layout.Config, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := customservices.Load(layout.CustomServices); err != nil {
		t.Fatal(err)
	}
	d, err := devices.Load(layout.Devices)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.MergeMetadata([]devices.Device{{ID: "test-device", Name: "Before"}}); err != nil {
		t.Fatal(err)
	}
	m := engineconfig.New(layout.StageRoot, filepath.Join(base, "unused-backup"))
	if _, err := m.Stage("sing-box", "main", "{unfinished"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Stage("usque", "main", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Stage("nfqws2", "exclude-list", "unrelated.example"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(layout.ProviderRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	return layout
}

func testPayload(t *testing.T) privatebackup.Payload {
	t.Helper()
	p := privatebackup.NewPayload("0.18.1-dev")
	p.CreatedAt = "2026-01-01T00:00:00Z"
	p.Services = map[string]config.ServiceState{"youtube": {Enabled: true, Route: "usque"}, "custom-import": {Enabled: true, Route: "direct"}}
	p.CustomServices = []catalog.Service{{ID: "custom-import", Name: "Imported", Category: "Custom", Domains: []string{"import.example"}, Strategy: []string{"direct"}}}
	p.Devices = []devices.Device{{ID: "test-device", Name: "After"}}
	for _, f := range []struct{ engine, content string }{{"nfqws2", "youtube.com\n"}, {"sing-box", `{"synthetic":"proxy"}`}, {"usque", `{"synthetic":"session"}`}} {
		id := "main"
		if f.engine == "nfqws2" {
			id = "user-list"
		}
		p.EngineFiles = append(p.EngineFiles, privatebackup.EngineFile{EngineID: f.engine, FileID: id, Content: f.content, SHA256: privatebackup.Sum([]byte(f.content)), Sensitive: f.engine != "nfqws2"})
	}
	raw := `{"id":"synthetic-device","private_key":"synthetic-key","access_token":"synthetic-token","endpoint_pub_key":"synthetic-peer","endpoint_v4":"162.159.198.2"}`
	p.ProviderSnapshots = []privatebackup.ProviderSnapshot{{Provider: "cloudflare", ID: "cf-" + strings.Repeat("a", 32), SourceKind: cloudflareprovider.SourceUSQUE, Content: raw, SHA256: privatebackup.Sum([]byte(raw)), ImportedAt: "2026-01-01T00:00:00Z"}}
	if err := privatebackup.Seal(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

func imagesOnDisk(t *testing.T, layout Layout) map[string]restorejournal.Image {
	t.Helper()
	paths := map[string]string{"config": layout.Config, "custom_services": layout.CustomServices, "devices": layout.Devices, "provider_cloudflare": filepath.Join(layout.ProviderRoot, "accounts.private.json")}
	for _, ref := range []engineconfig.DraftRef{{EngineID: "nfqws2", FileID: "user-list"}, {EngineID: "sing-box", FileID: "main"}, {EngineID: "usque", FileID: "main"}, {EngineID: "xray", FileID: "main"}, {EngineID: "nfqws2", FileID: "exclude-list"}} {
		paths[draftID(ref.EngineID, ref.FileID)] = filepath.Join(layout.StageRoot, ref.EngineID, ref.FileID+".draft")
	}
	out := map[string]restorejournal.Image{}
	for id, path := range paths {
		image, err := restorejournal.ReadFileImage(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		out[id] = image
	}
	return out
}
func requireImages(t *testing.T, layout Layout, want map[string]restorejournal.Image) {
	t.Helper()
	got := imagesOnDisk(t, layout)
	for id, image := range want {
		if got[id].Exists != image.Exists || !bytes.Equal(got[id].Data, image.Data) {
			t.Fatalf("changed target %s", id)
		}
	}
}

func TestCleanStartupIsLazyAndHasLifetimeLease(t *testing.T) {
	layout := testLayout(t.TempDir())
	ctx := context.Background()
	c, out, err := Open(ctx, layout)
	if err != nil || out != restorejournal.Clean {
		t.Fatal(out, err)
	}
	defer c.Close()
	for _, path := range []string{layout.Config, layout.CustomServices, layout.Devices, layout.StageRoot, layout.ProviderRoot} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("clean recovery touched unrelated path")
		}
	}
	if second, _, err := Open(ctx, layout); !errors.Is(err, restorejournal.ErrBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatal("second instance not rejected", err)
	}
	if err := c.StartRuntime(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RestoreOffline(ctx, testPayload(t), map[string]bool{"youtube": true}); !errors.Is(err, ErrRuntimeStarted) {
		t.Fatal("offline API remained writable", err)
	}
	c.Close()
	if _, err := c.RestoreOffline(ctx, testPayload(t), nil); !errors.Is(err, restorejournal.ErrRecovery) {
		t.Fatal("closed coordinator writable")
	}
	if err := c.StartRuntime(); err == nil {
		t.Fatal("closed coordinator started")
	}
	next, _, err := Open(ctx, layout)
	if err != nil {
		t.Fatal("lease did not release", err)
	}
	next.Close()
}

func TestOfflineCombinedRestorePreservesLiveAndUnrelatedState(t *testing.T) {
	layout := seedLayout(t, t.TempDir())
	ctx := context.Background()
	before := imagesOnDisk(t, layout)
	c, _, err := Open(ctx, layout)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := testPayload(t)
	out, err := c.RestoreOffline(ctx, p, map[string]bool{"youtube": true})
	if err != nil || out != restorejournal.Applied {
		t.Fatal(out, err)
	}
	after := imagesOnDisk(t, layout)
	for id := range after {
		if id != draftID("nfqws2", "exclude-list") && id != draftID("xray", "main") && bytes.Equal(after[id].Data, before[id].Data) {
			t.Fatalf("target %s was not written", id)
		}
	}
	if !bytes.Equal(after[draftID("nfqws2", "exclude-list")].Data, before[draftID("nfqws2", "exclude-list")].Data) {
		t.Fatal("unrelated draft changed")
	}
	old, _, _ := config.InspectBytes(before["config"].Data)
	now, _, err := config.InspectBytes(after["config"].Data)
	if err != nil || !reflect.DeepEqual(old.AppliedServices, now.AppliedServices) || old.SafeMode != now.SafeMode || old.AppliedRevision != now.AppliedRevision || old.Listen != now.Listen || !reflect.DeepEqual(old.EngineOrder, now.EngineOrder) {
		t.Fatal("live config fields changed")
	}
	if now.Services["youtube"].Route != "usque" {
		t.Fatal("desired state not restored")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(layout.Config), "unused-backup")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("live backups touched")
	}
	// New caches load only after the offline transaction completed.
	if err := c.StartRuntime(); err != nil {
		t.Fatal(err)
	}
	provider, err := cloudflareprovider.OpenStore(layout.ProviderRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	accounts, err := provider.List(ctx)
	if err != nil || len(accounts) != 1 || accounts[0].Verification != "imported-unverified" {
		t.Fatal("profile promoted or lost")
	}
	custom, err := customservices.Load(layout.CustomServices)
	if err != nil || len(custom.List()) != 1 {
		t.Fatal("catalog cache not restored", err)
	}
	device, err := devices.Load(layout.Devices)
	if err != nil || device.Known()[0].Name != "After" {
		t.Fatal("device cache not restored", err)
	}
}

func TestOfflinePreflightAndCancellationNeverPartiallyWrite(t *testing.T) {
	for _, failure := range []string{"unknown-service", "bad-digest", "busy-device", "canceled", "bad-provider", "budget"} {
		t.Run(failure, func(t *testing.T) {
			layout := seedLayout(t, t.TempDir())
			before := imagesOnDisk(t, layout)
			ctx := context.Background()
			c, _, err := Open(ctx, layout)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			p := testPayload(t)
			switch failure {
			case "unknown-service":
				p.Services["missing"] = config.ServiceState{Route: "direct"}
				privatebackup.Seal(&p)
			case "bad-digest":
				p.Digest = strings.Repeat("0", 64)
			case "busy-device":
				busy, err := devices.OpenRestoreTarget(layout.Devices)
				if err != nil {
					t.Fatal(err)
				}
				defer busy.Close()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "bad-provider":
				p.ProviderSnapshots[0].Content = `{}`
				p.ProviderSnapshots[0].SHA256 = privatebackup.Sum([]byte(`{}`))
				privatebackup.Seal(&p)
			case "budget":
				// Each draft is valid and <=2 MiB, but before+after of all targets
				// exceeds the global journal limit. The fourth image causes no write.
				p.EngineFiles = nil
				m := engineconfig.New(layout.StageRoot, filepath.Join(filepath.Dir(layout.Config), "unused-backup"))
				for _, engineID := range []string{"sing-box", "usque", "xray"} {
					old := `{"padding":"` + strings.Repeat("a", (2<<20)-32) + `"}`
					fresh := strings.ReplaceAll(old, "a", "b")
					if _, err := m.Stage(engineID, "main", old); err != nil {
						t.Fatal(err)
					}
					p.EngineFiles = append(p.EngineFiles, privatebackup.EngineFile{EngineID: engineID, FileID: "main", Content: fresh, SHA256: privatebackup.Sum([]byte(fresh)), Sensitive: true})
				}
				before = imagesOnDisk(t, layout)
				if err := privatebackup.Seal(&p); err != nil {
					t.Fatal(err)
				}
			}
			out, err := c.RestoreOffline(ctx, p, map[string]bool{"youtube": true})
			if err == nil || out != restorejournal.Clean {
				t.Fatalf("preflight: %s %v", out, err)
			}
			requireImages(t, layout, before)
			if len(c.acquired) != 0 {
				t.Fatal("preflight leaked leases")
			}
			if _, err := os.Stat(filepath.Join(layout.JournalRoot, "restore.private.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("preflight published journal")
			}
		})
	}
}

func TestCombinedRollbackAndUnknownStateFence(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "external"}[external], func(t *testing.T) {
			layout := seedLayout(t, t.TempDir())
			before := imagesOnDisk(t, layout)
			ctx := context.Background()
			c, _, err := Open(ctx, layout)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.beforeWrite = func(id string) error {
				if id != "provider_cloudflare" {
					return nil
				}
				if external {
					if err := os.WriteFile(layout.Config, append(bytes.Clone(before["config"].Data), ' '), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return errors.New("synthetic failure with private-marker")
			}
			out, err := c.RestoreOffline(ctx, testPayload(t), map[string]bool{"youtube": true})
			if err == nil {
				t.Fatal("injected failure lost")
			}
			if external {
				if out != restorejournal.Blocked || !c.blocked {
					t.Fatal("unknown state not blocked")
				}
				if err := c.StartRuntime(); err == nil {
					t.Fatal("blocked coordinator started runtime")
				}
				if _, err := c.RestoreOffline(ctx, testPayload(t), nil); !errors.Is(err, restorejournal.ErrRecovery) {
					t.Fatal("blocked coordinator retried")
				}
				data, _ := os.ReadFile(layout.Config)
				if !bytes.Equal(data, append(bytes.Clone(before["config"].Data), ' ')) {
					t.Fatal("external change overwritten")
				}
			} else {
				if out != restorejournal.RolledBack {
					t.Fatal(out, err)
				}
				requireImages(t, layout, before)
			}
			if strings.Contains(err.Error(), "private-marker") {
				t.Fatal("cause leaked")
			}
		})
	}
}

func TestCancellationDuringCombinedWriteRestoresAllDrafts(t *testing.T) {
	layout := seedLayout(t, t.TempDir())
	before := imagesOnDisk(t, layout)
	c, _, err := Open(context.Background(), layout)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.afterWrite = func(id string) {
		if id == draftID("usque", "main") {
			cancel()
		}
	}
	out, err := c.RestoreOffline(ctx, testPayload(t), map[string]bool{"youtube": true})
	if out != restorejournal.RolledBack || !errors.Is(err, restorejournal.ErrAborted) {
		t.Fatal("cancellation did not roll back", out, err)
	}
	requireImages(t, layout, before)
	if err := c.StartRuntime(); err != nil {
		t.Fatal("successful rollback left coordinator fenced", err)
	}
}

func TestLayoutRejectsOverlappingDestinationsBeforePreparation(t *testing.T) {
	for _, variant := range []string{"same-file", "stage-journal", "provider-stage", "file-in-stage", "blank"} {
		layout := testLayout(t.TempDir())
		switch variant {
		case "same-file":
			layout.Devices = layout.Config
		case "stage-journal":
			layout.StageRoot = layout.JournalRoot
		case "provider-stage":
			layout.ProviderRoot = filepath.Join(layout.StageRoot, "provider")
		case "file-in-stage":
			layout.Config = filepath.Join(layout.StageRoot, "config.json")
		case "blank":
			layout.Config = ""
		}
		if c, _, err := Open(context.Background(), layout); !errors.Is(err, restorejournal.ErrInvalid) {
			if c != nil {
				c.Close()
			}
			t.Fatal("invalid layout accepted", variant, err)
		}
		if _, err := os.Stat(layout.JournalRoot); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid layout created journal directory")
		}
	}
}
