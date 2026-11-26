package privaterestore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func initializedServiceControlLayout(t *testing.T) Layout {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("strict original ownership requires Linux")
	}
	layout := testLayout(t.TempDir())
	c, out, err := Open(context.Background(), layout)
	if err != nil || out != restorejournal.Clean {
		t.Fatal(out, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	return layout
}

func TestOfflineServiceControlNeverCreatesMissingGenerationOrMarker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, rootExists := range []bool{false, true} {
		layout := testLayout(t.TempDir())
		if rootExists {
			if err := os.Mkdir(layout.JournalRoot, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		c, err := OpenForOfflineServiceControl(ctx, layout)
		if c != nil || err == nil {
			if c != nil {
				_ = c.Close()
			}
			t.Fatal("missing lifetime owner admitted")
		}
		if rootExists {
			if entries, err := os.ReadDir(layout.JournalRoot); err != nil || len(entries) != 0 {
				t.Fatal("existing-only opening created a marker", err)
			}
		} else if _, err := os.Stat(layout.JournalRoot); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("existing-only opening created a generation", err)
		}
		for _, path := range []string{layout.Config, layout.CustomServices, layout.Devices, layout.StageRoot, layout.ProviderRoot} {
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("existing-only opening created target", path, err)
			}
		}
	}
}

func TestOfflineServiceControlRetainsEachGenerationWithoutTargetOpening(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("strict original ownership requires Linux")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	base := t.TempDir()
	layout := testLayout(base)
	var held []*Coordinator
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			_ = held[i].Close()
		}
	}()
	for i, generation := range []string{"private-restore", "private-restore-nodes-v1", "private-restore-native-v1", "private-restore-feeds-v1"} {
		layout.JournalRoot = filepath.Join(base, generation)
		if i >= 1 {
			layout.NodeRoot = filepath.Join(base, "nodes")
		}
		if i >= 2 {
			layout.WarpRoot = filepath.Join(base, "warp")
		}
		if i >= 3 {
			layout.FeedRoot = filepath.Join(base, "subscriptions-private")
		}
		seed, _, err := Open(ctx, layout)
		if err != nil {
			t.Fatal(err)
		}
		if err := seed.Close(); err != nil {
			t.Fatal(err)
		}
		c, err := OpenForOfflineServiceControl(ctx, layout)
		if err != nil {
			t.Fatal(generation, err)
		}
		held = append(held, c)
		called := false
		if err := c.WithOfflineServiceControl(ctx, layout.Config, func(actual context.Context) error {
			called = true
			if actual != ctx {
				t.Fatal("callback received a substituted context")
			}
			other, _, err := Open(ctx, layout)
			if other != nil || !errors.Is(err, restorejournal.ErrBusy) {
				if other != nil {
					_ = other.Close()
				}
				t.Fatal("ordinary startup bypassed original lifetime", err)
			}
			return nil
		}); err != nil || !called {
			t.Fatal("original callback refused", generation, err)
		}
		if len(c.acquired) != 0 {
			t.Fatal("existing-only admission opened a target")
		}
		if _, err := os.Stat(filepath.Join(layout.JournalRoot, "restore.private.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("idle callback created a receipt", err)
		}
	}
	for _, path := range []string{layout.Config, layout.CustomServices, layout.Devices, layout.StageRoot, layout.ProviderRoot, layout.NodeRoot, layout.WarpRoot, layout.FeedRoot} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("existing-only admission materialized target", path, err)
		}
	}
}

func TestOfflineServiceControlRefusesPreparedRestoreWithoutReplay(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("strict original ownership requires Linux")
	}
	c, layout, stores := onlineFixture(t)
	before := imagesOnDisk(t, layout)
	c.afterWrite = func(string) { panic("modeled interrupted actual restore") }
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("actual prepared write was not reached")
			}
		}()
		_, _ = c.RestoreOnline(context.Background(), testPayload(t), map[string]bool{"youtube": true}, stores)
	}()
	if journalState(t, layout) != "prepared" {
		t.Fatal("missing actual pending transaction")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	partial := imagesOnDisk(t, layout)
	journal := filepath.Join(layout.JournalRoot, "restore.private.json")
	raw, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, err := OpenForOfflineServiceControl(ctx, layout)
	if got != nil || !errors.Is(err, restorejournal.ErrRecovery) {
		if got != nil {
			_ = got.Close()
		}
		t.Fatal("pending restore admitted/replayed", err)
	}
	requireImages(t, layout, partial)
	if after, err := os.ReadFile(journal); err != nil || !bytes.Equal(raw, after) {
		t.Fatal("pending journal changed", err)
	}
	next, out, err := Open(ctx, layout)
	if err != nil || out != restorejournal.RolledBack {
		t.Fatal("ordinary recovery no longer owns retained transaction", out, err)
	}
	defer next.Close()
	requireImages(t, layout, before)
}

func TestOfflineServiceControlRejectsWrongLifetimeContextAndBinding(t *testing.T) {
	layout := initializedServiceControlLayout(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := OpenForOfflineServiceControl(ctx, layout)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	called := false
	callback := func(context.Context) error { called = true; return nil }
	cancelled, end := context.WithCancel(ctx)
	end()
	for _, badContext := range []context.Context{nil, context.Background(), cancelled} {
		if err := c.WithOfflineServiceControl(badContext, layout.Config, callback); err == nil {
			t.Fatal("invalid/unbounded context admitted")
		}
	}
	if err := c.WithOfflineServiceControl(ctx, layout.Config+".other", callback); err == nil {
		t.Fatal("different configured target admitted")
	}
	if err := c.StartRuntime(); err != nil {
		t.Fatal(err)
	}
	if err := c.WithOfflineServiceControl(ctx, layout.Config, callback); !errors.Is(err, restorejournal.ErrRecovery) {
		t.Fatal("runtime handover left offline interface open", err)
	}
	if called {
		t.Fatal("refused admission invoked callback")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	stop, err := OpenForOfflineNFQWS2Stop(ctx, layout)
	if err != nil {
		t.Fatal(err)
	}
	defer stop.Close()
	if err := stop.WithOfflineServiceControl(ctx, layout.Config, callback); !errors.Is(err, restorejournal.ErrRecovery) || called {
		t.Fatal("service control borrowed Stop-only admission", err)
	}
}

func TestOfflineServiceControlReportsClosingOwnerChange(t *testing.T) {
	layout := initializedServiceControlLayout(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := OpenForOfflineServiceControl(ctx, layout)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(layout.JournalRoot, ".restore.lock")
	err = c.WithOfflineServiceControl(ctx, layout.Config, func(context.Context) error {
		data, err := os.ReadFile(marker)
		if err != nil {
			return err
		}
		if err := os.Rename(marker, marker+".retained"); err != nil {
			return err
		}
		return os.WriteFile(marker, data, 0o600)
	})
	if !errors.Is(err, restorejournal.ErrUnavailable) || !c.blocked {
		t.Fatal("changed closing owner reported successful callback", err)
	}
	if !errors.Is(c.Close(), restorejournal.ErrUnavailable) {
		t.Fatal("changed closing owner reported clean close")
	}
}

func TestOfflineServiceControlCannotRenewOriginalContext(t *testing.T) {
	layout := initializedServiceControlLayout(t)
	original, cancelOriginal := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelOriginal()
	c, err := OpenForOfflineServiceControl(original, layout)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	replacement, cancelReplacement := context.WithTimeout(context.Background(), time.Minute)
	defer cancelReplacement()
	called := false
	callback := func(context.Context) error { called = true; return nil }
	if err := c.WithOfflineServiceControl(replacement, layout.Config, callback); err == nil || called {
		t.Fatal("a longer unrelated context replaced the original lifetime", err)
	}
	cancelOriginal()
	if err := c.WithOfflineServiceControl(replacement, layout.Config, callback); err == nil || called {
		t.Fatal("a fresh context revived the cancelled original lifetime", err)
	}
}
