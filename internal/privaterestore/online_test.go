package privaterestore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func liveStores(t *testing.T, layout Layout) Stores {
	t.Helper()
	var s Stores
	var err error
	if s.Config, err = config.Load(layout.Config); err != nil {
		t.Fatal(err)
	}
	if s.Custom, err = customservices.Load(layout.CustomServices); err != nil {
		t.Fatal(err)
	}
	if s.Devices, err = devices.Load(layout.Devices); err != nil {
		t.Fatal(err)
	}
	s.Engines = engineconfig.New(layout.StageRoot, filepath.Join(filepath.Dir(layout.Config), "backups"))
	if s.Provider, err = cloudflareprovider.OpenStore(layout.ProviderRoot); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Provider.Close() })
	return s
}

func onlineFixture(t *testing.T) (*Coordinator, Layout, Stores) {
	t.Helper()
	l := seedLayout(t, t.TempDir())
	c, _, err := Open(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	s := liveStores(t, l)
	if err := c.StartRuntime(); err != nil {
		t.Fatal(err)
	}
	return c, l, s
}

func requireLiveCaches(t *testing.T, l Layout, s Stores) {
	t.Helper()
	cfg, err := config.Load(l.Config)
	if err != nil || !reflect.DeepEqual(cfg.Get(), s.Config.Get()) {
		t.Fatal("configuration cache differs from disk", err)
	}
	custom, err := customservices.Load(l.CustomServices)
	if err != nil || !reflect.DeepEqual(custom.List(), s.Custom.List()) {
		t.Fatal("catalog cache differs from disk", err)
	}
	d, err := devices.Load(l.Devices)
	if err != nil || !reflect.DeepEqual(d.Known(), s.Devices.Known()) {
		t.Fatal("device cache differs from disk", err)
	}
}

func journalState(t *testing.T, l Layout) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(l.JournalRoot, "restore.private.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		State string `json:"state"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("invalid journal")
	}
	return doc.State
}

func TestOnlineRestoreUpdatesCachesAndPreservesLive(t *testing.T) {
	c, l, s := onlineFixture(t)
	before := s.Config.Get()
	called := 0
	c.beforeHandover = func() error {
		called++
		if journalState(t, l) != "committed" {
			t.Fatal("journal cleared before cache handover")
		}
		// The in-memory mutex AND disk writer lease must still be owned.
		if session, err := s.Config.BeginRestore(context.Background()); err == nil {
			session.Close()
			t.Fatal("session released early")
		}
		requireWriterExclusion(t, l)
		return nil
	}
	out, err := c.RestoreOnline(context.Background(), testPayload(t), map[string]bool{"youtube": true}, s)
	if err != nil || out != restorejournal.Applied || called != 1 {
		t.Fatal(out, err, called)
	}
	requireLiveCaches(t, l, s)
	after := s.Config.Get()
	if after.Services["youtube"].Route != "usque" || !reflect.DeepEqual(before.AppliedServices, after.AppliedServices) || before.SafeMode != after.SafeMode || !reflect.DeepEqual(before.EngineOrder, after.EngineOrder) {
		t.Fatal("wrong live/draft boundaries")
	}
	if journalState(t, l) != "idle" {
		t.Fatal("journal not finalized")
	}
	// Sessions and slot wrappers are reusable; no second file lease deadlock.
	c.beforeHandover = nil
	if _, err := c.RestoreOnline(context.Background(), testPayload(t), map[string]bool{"youtube": true}, s); err != nil {
		t.Fatal(err)
	}
	if err := s.Config.UpdateService("youtube", config.ServiceState{Route: "direct"}); err != nil {
		t.Fatal("ordinary writer did not resume", err)
	}
}

func TestOnlineRollbackEveryWriteRestoresCachesAndDraftImages(t *testing.T) {
	for _, failedID := range []string{"config", "custom_services", "devices", draftID("nfqws2", "user-list"), draftID("sing-box", "main"), draftID("usque", "main"), "provider_cloudflare"} {
		t.Run(failedID, func(t *testing.T) {
			c, l, s := onlineFixture(t)
			before := imagesOnDisk(t, l)
			c.beforeWrite = func(id string) error {
				if id == failedID {
					return errors.New("synthetic private failure")
				}
				return nil
			}
			c.beforeHandover = func() error {
				if journalState(t, l) != "prepared" {
					t.Fatal("rollback journal cleared too soon")
				}
				return nil
			}
			out, err := c.RestoreOnline(context.Background(), testPayload(t), map[string]bool{"youtube": true}, s)
			if err == nil || out != restorejournal.RolledBack {
				t.Fatal(out, err)
			}
			requireImages(t, l, before)
			requireLiveCaches(t, l, s)
			if c.blocked {
				t.Fatal("verified rollback fenced coordinator")
			}
			c.beforeWrite, c.beforeHandover = nil, nil
			if _, err := c.RestoreOnline(context.Background(), testPayload(t), map[string]bool{"youtube": true}, s); err != nil {
				t.Fatal("retry failed", err)
			}
		})
	}
}

func TestOnlineRejectsWrongStoreBindingsBeforeWrites(t *testing.T) {
	for _, kind := range []string{"config", "custom", "devices", "engines", "provider"} {
		t.Run(kind, func(t *testing.T) {
			c, l, s := onlineFixture(t)
			otherLayout := seedLayout(t, t.TempDir())
			other := liveStores(t, otherLayout)
			before, otherBefore := imagesOnDisk(t, l), imagesOnDisk(t, otherLayout)
			switch kind {
			case "config":
				s.Config = other.Config
			case "custom":
				s.Custom = other.Custom
			case "devices":
				s.Devices = other.Devices
			case "engines":
				s.Engines = other.Engines
			case "provider":
				s.Provider = other.Provider
			}
			out, err := c.RestoreOnline(context.Background(), testPayload(t), map[string]bool{"youtube": true}, s)
			if out != restorejournal.Clean || !errors.Is(err, restorejournal.ErrInvalid) {
				t.Fatal(out, err)
			}
			requireImages(t, l, before)
			requireImages(t, otherLayout, otherBefore)
			if _, err := os.Stat(filepath.Join(l.JournalRoot, "restore.private.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("mismatch published plan")
			}
			if len(c.acquired) != 0 {
				t.Fatal("offline factory used online")
			}
			for _, slot := range c.slots {
				if slot.target != nil {
					t.Fatal("session retained")
				}
			}
		})
	}
}

func TestOnlineCancellationRollsBackAndReleases(t *testing.T) {
	c, l, s := onlineFixture(t)
	before := imagesOnDisk(t, l)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.afterWrite = func(id string) {
		if id == "custom_services" {
			cancel()
		}
	}
	out, err := c.RestoreOnline(ctx, testPayload(t), map[string]bool{"youtube": true}, s)
	if out != restorejournal.RolledBack || err == nil {
		t.Fatal(out, err)
	}
	requireImages(t, l, before)
	requireLiveCaches(t, l, s)
}

func TestOnlinePanicPreservesRecoveryAndFencesCoordinator(t *testing.T) {
	c, l, s := onlineFixture(t)
	before := imagesOnDisk(t, l)
	c.afterWrite = func(string) { panic("synthetic private panic") }
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic seam not reached")
			}
		}()
		_, _ = c.RestoreOnline(context.Background(), testPayload(t), map[string]bool{"youtube": true}, s)
	}()
	if !c.blocked || journalState(t, l) != "prepared" {
		t.Fatal("panic discarded recovery state")
	}
	for _, slot := range c.slots {
		if slot.target != nil {
			t.Fatal("panic leaked session")
		}
	}
	c.Close()
	next, out, err := Open(context.Background(), l)
	if err != nil || out != restorejournal.RolledBack {
		t.Fatal(out, err)
	}
	next.Close()
	requireImages(t, l, before)
}

func TestOnlineFailedHandoverRetainsJournalUntilStartup(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "callback", true: "cache-read"}[corrupt], func(t *testing.T) {
			c, l, s := onlineFixture(t)
			var committed []byte
			c.beforeHandover = func() error {
				var err error
				committed, err = os.ReadFile(l.Config)
				if err != nil {
					t.Fatal(err)
				}
				if corrupt {
					return os.WriteFile(l.Config, []byte("invalid private config"), 0600)
				}
				return errors.New("synthetic handover failure")
			}
			out, err := c.RestoreOnline(context.Background(), testPayload(t), map[string]bool{"youtube": true}, s)
			if out != restorejournal.Blocked || !errors.Is(err, restorejournal.ErrRecovery) || !c.blocked {
				t.Fatal(out, err)
			}
			if journalState(t, l) != "committed" {
				t.Fatal("recovery evidence lost")
			}
			if _, err := c.RestoreOnline(context.Background(), testPayload(t), nil, s); !errors.Is(err, restorejournal.ErrRecovery) {
				t.Fatal("uncertain coordinator accepted another restore")
			}
			c.Close()
			if corrupt {
				if next, _, err := Open(context.Background(), l); err == nil {
					next.Close()
					t.Fatal("corrupt target silently accepted")
				}
				if err := os.WriteFile(l.Config, committed, 0600); err != nil {
					t.Fatal(err)
				}
			}
			next, out, err := Open(context.Background(), l)
			if err != nil || out != restorejournal.Applied {
				t.Fatal(out, err)
			}
			next.Close()
			if journalState(t, l) != "idle" {
				t.Fatal("startup did not finish handover recovery")
			}
		})
	}
}

func TestOnlineUnknownImageBlocksWithoutOverwriting(t *testing.T) {
	c, l, s := onlineFixture(t)
	c.afterWrite = func(id string) {
		if id == "config" {
			raw, err := os.ReadFile(l.Config)
			if err != nil {
				t.Fatal(err)
			}
			cfg, _, err := config.InspectBytes(raw)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Services["youtube"] = config.ServiceState{Route: "direct"}
			raw, _ = json.Marshal(cfg)
			if err := os.WriteFile(l.Config, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	out, err := c.RestoreOnline(context.Background(), testPayload(t), map[string]bool{"youtube": true}, s)
	if out != restorejournal.Blocked || err == nil {
		t.Fatal(out, err)
	}
	if journalState(t, l) != "prepared" {
		t.Fatal("lost uncertain plan")
	}
	if s.Config.Get().Services["youtube"].Route != "direct" {
		t.Fatal("external edit overwritten")
	}
	if strings.Contains(err.Error(), "youtube") {
		t.Fatal("private cause exposed")
	}
}
