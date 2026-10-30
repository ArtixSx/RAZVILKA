package privaterestore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestOfflineNFQWS2OpenRefusesPreparedRestoreWithoutChangingTargets(t *testing.T) {
	c, layout, stores := onlineFixture(t)
	before := imagesOnDisk(t, layout)
	c.afterWrite = func(string) { panic("modeled process interruption after original target write") }
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("partial restore was not reached")
			}
		}()
		_, _ = c.RestoreOnline(context.Background(), testPayload(t), map[string]bool{"youtube": true}, stores)
	}()
	if journalState(t, layout) != "prepared" {
		t.Fatal("actual private restore did not retain pending intent")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	partial := imagesOnDisk(t, layout)
	journalPath := filepath.Join(layout.JournalRoot, "restore.private.json")
	raw, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, err := OpenForOfflineNFQWS2Stop(ctx, layout)
	if got != nil || !errors.Is(err, restorejournal.ErrRecovery) {
		if got != nil {
			_ = got.Close()
		}
		t.Fatal("explicit Stop replayed pending private restore", err)
	}
	requireImages(t, layout, partial)
	after, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("explicit Stop changed the restore journal", err)
	}
	// The restrictive entry point must neither weaken nor strand ordinary
	// private recovery: its unchanged original rollback still works afterward.
	next, outcome, err := Open(ctx, layout)
	if err != nil || outcome != restorejournal.RolledBack {
		t.Fatal("normal recovery no longer works", outcome, err)
	}
	defer next.Close()
	requireImages(t, layout, before)
}

func TestOfflineNFQWS2OpenRetainsRealLeaseWithoutCreatingTargets(t *testing.T) {
	layout := testLayout(t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := OpenForOfflineNFQWS2Stop(ctx, layout)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, path := range []string{layout.Config, layout.CustomServices, layout.Devices, layout.StageRoot, layout.ProviderRoot} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("idle-only opening created a target", path, err)
		}
	}
	second, _, err := Open(ctx, layout)
	if second != nil || !errors.Is(err, restorejournal.ErrBusy) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatal("ordinary writer bypassed lifetime lease", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	second, _, err = Open(ctx, layout)
	if err != nil {
		t.Fatal("lifetime lease did not close", err)
	}
	_ = second.Close()
}

func TestOfflineNFQWS2OpenRequiresLiveBoundedContextBeforeCreatingJournal(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, context.Background(), cancelled} {
		layout := testLayout(t.TempDir())
		c, err := OpenForOfflineNFQWS2Stop(ctx, layout)
		if c != nil || err == nil {
			if c != nil {
				_ = c.Close()
			}
			t.Fatal("unbounded or invalid context admitted")
		}
		if _, err := os.Stat(layout.JournalRoot); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid admission wrote journal files")
		}
	}
}
