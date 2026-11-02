//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Real original journal FDs and Gate; terminal probe/join rows are explicitly
// MODELED. This cannot establish native service health or router readiness.
func mihomoTransitArchiveFileModel(t *testing.T) (*mihomoTransitArchiveCursor, context.Context, *operationgate.ExclusiveCleanupReview) {
	t.Helper()
	h, archive, after, r := mihomoTransitArchiveOwnerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	controlRoot := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlRoot); err != nil {
		t.Fatal(err)
	}
	gate := &operationgate.Gate{}
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	r.control, err = gate.ReviewControlEpoch(held, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.control.Close() })
	cleanup, err := gate.ReviewExclusiveCleanup(held)
	if err != nil {
		t.Fatal(err)
	}
	var before Execution
	if err := json.Unmarshal(h.OriginBefore, &before); err != nil {
		t.Fatal(err)
	}
	r.scope.execution = &before
	if err := r.publishRecords(h.OriginBefore); err != nil {
		t.Fatal(err)
	}
	r.scope.retained, r.scope.pending = true, true
	selected := map[string]*executionTransitResource{}
	for _, row := range archive.Resources {
		owner := &executionTransitResource{finished: true, admitted: true, spec: *row.NodeTransit, digest: row.Generation, effects: row.EffectsDigest}
		r.scope.issued[row.ID] = owner
		selected[row.ID] = owner
	}
	image, err := json.Marshal(archive)
	if err != nil {
		t.Fatal(err)
	}
	afterImage, _ := json.Marshal(after)
	c := &mihomoTransitArchiveCursor{owner: r, before: bytes.Clone(h.OriginBefore), after: afterImage, archive: archive, image: image, selected: selected}
	c.self, r.transitHistory = c, c
	t.Cleanup(func() {
		if c.file != nil && !c.fileClosed {
			_ = c.file.Close()
		}
		if c.root != nil && !c.rootClosed {
			_ = c.root.Close()
		}
	})
	return c, held, cleanup
}

func TestMihomoTransitArchiveOriginalWriterRetiresOnlyAfterAllACKs(t *testing.T) {
	c, ctx, cleanup := mihomoTransitArchiveFileModel(t)
	if !c.owner.scope.manager.HasPendingMihomoTransitHistory() {
		t.Fatal("original metadata custody not observable")
	}
	if err := c.create(ctx); err != nil {
		t.Fatal(err)
	}
	if len(c.owner.scope.issued) != 128 {
		t.Fatal("callbacks revoked before archive")
	}
	if err := c.publish(ctx); err != nil {
		t.Fatal(err)
	}
	if len(c.owner.scope.issued) != 128 || c.originACK {
		t.Fatal("archive ACK retired live callbacks")
	}
	archivePath := filepath.Join(c.owner.scope.managerRoot, c.relative, "execution.json")
	if err := c.finish(ctx, cleanup); err != nil {
		t.Fatal(err)
	}
	if !c.complete || c.owner.transitHistory != nil || c.owner.scope.pending || len(c.owner.scope.issued) != 0 || len(c.owner.historyIDs) != 128 || !c.fileClosed || !c.rootClosed {
		t.Fatal("incomplete original metadata handoff")
	}
	if c.owner.scope.manager.HasPendingMihomoTransitHistory() {
		t.Fatal("completed history reported as native pending cleanup")
	}
	for _, path := range []string{filepath.Join(c.owner.scope.root, "execution.json"), filepath.Join(c.owner.scope.managerRoot, "latest-execution.json")} {
		raw, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(raw, c.after) {
			t.Fatal("original writer did not preserve exact After", err)
		}
	}
	raw, err := os.ReadFile(archivePath)
	if err != nil || !bytes.Equal(raw, c.image) {
		t.Fatal("archive bytes lost", err)
	}
	if version, _, err := InspectRetainedExecutionReadVersion(ctx, c.owner.scope.managerRoot); err != nil || version != 8 {
		t.Fatal(version, err)
	}
	if err := c.finish(ctx, cleanup); err == nil {
		t.Fatal("completed cursor replayed")
	}
}

func TestMihomoTransitArchiveForeignReplacementAndCanceledCloseRetainCallbacks(t *testing.T) {
	for _, change := range []string{"archive", "origin", "cancel", "copied", "closed-file"} {
		t.Run(change, func(t *testing.T) {
			c, ctx, cleanup := mihomoTransitArchiveFileModel(t)
			if err := c.create(ctx); err != nil {
				t.Fatal(err)
			}
			if err := c.publish(ctx); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "archive", "origin":
				path := filepath.Join(c.owner.scope.managerRoot, c.relative, "execution.json")
				if change == "origin" {
					path = filepath.Join(c.owner.scope.managerRoot, "latest-execution.json")
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			case "closed-file":
				if err := c.file.Close(); err != nil {
					t.Fatal(err)
				}
			case "copied":
				forged := *c // No synchronization primitives; opaque self must refuse.
				if err := forged.finish(ctx, cleanup); err == nil {
					t.Fatal("copied cursor accepted")
				}
				return
			}
			if err := c.finish(ctx, cleanup); err == nil || change == "closed-file" && !errors.Is(err, os.ErrClosed) {
				t.Fatal("changed original accepted")
			}
			if len(c.owner.scope.issued) != 128 || !c.owner.scope.pending || c.complete {
				t.Fatal("refusal lost original callback custody")
			}
		})
	}
}

func TestMihomoTransitArchiveOriginalSlotPartialPublicationRetry(t *testing.T) {
	c, ctx, cleanup := mihomoTransitArchiveFileModel(t)
	if err := c.create(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.publish(ctx); err != nil {
		t.Fatal(err)
	}
	// A refusal-only cut in the REAL finish -> Manager original writer path,
	// after transaction publication/fsync and before latest publication.
	cut := errors.New("modeled original latest publication refusal")
	once := false
	c.fault = func(stage string) error {
		if stage != "origin-before-latest" {
			t.Fatal("unexpected private cut", stage)
		}
		if !once {
			once = true
			return cut
		}
		return nil
	}
	if err := c.finish(ctx, cleanup); !errors.Is(err, cut) {
		t.Fatal("actual finish exception lost", err)
	}
	if !once || c.owner.scope.failure != nil || !c.owner.scope.pending || c.originACK || len(c.owner.scope.issued) != 128 || c.owner.transitHistory != c {
		t.Fatal("partial write poisoned or released original custody")
	}
	if !bytes.Equal(c.owner.records.images[0], c.after) || !bytes.Equal(c.owner.records.images[1], c.before) {
		t.Fatal("test did not exercise actual partial original publication")
	}
	if err := c.owner.records.current(ctx, true); err == nil {
		t.Fatal("partial pair looked complete")
	}
	if err := c.finish(ctx, cleanup); err != nil {
		t.Fatal(err)
	}
	if !c.complete || len(c.owner.scope.issued) != 0 {
		t.Fatal("same cursor did not finish")
	}
	if !errors.Is(c.finish(ctx, cleanup), ErrExecutionJournal) {
		t.Fatal("late cursor accepted")
	}
}

func TestMihomoTransitArchiveNeverClearsUnrelatedScopeFailure(t *testing.T) {
	c, ctx, cleanup := mihomoTransitArchiveFileModel(t)
	if err := c.create(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.publish(ctx); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("original unrelated native failure")
	c.owner.scope.failure = failure
	if err := c.finish(ctx, cleanup); !errors.Is(err, failure) {
		t.Fatal("original exception hidden", err)
	}
	if c.owner.scope.failure != failure || !c.owner.scope.pending || c.complete || len(c.owner.scope.issued) != 128 || !bytes.Equal(c.owner.records.images[0], c.before) || !bytes.Equal(c.owner.records.images[1], c.before) {
		t.Fatal("foreign failure bypassed or callback custody lost")
	}
}

func TestMihomoTransitArchiveRecordedCloseFailureRemainsVisibleOnEveryRetry(t *testing.T) {
	c, ctx, cleanup := mihomoTransitArchiveFileModel(t)
	if err := c.create(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.publish(ctx); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("modeled recorded original close failure")
	c.closeErr = failure
	for i := 0; i < 2; i++ {
		for _, call := range []func() error{func() error { return c.create(ctx) }, func() error { return c.current(ctx) }, func() error { return c.archiveCurrent(ctx) }, func() error { return c.closeArchive(ctx) }, func() error { return c.finish(ctx, cleanup) }} {
			if err := call(); !errors.Is(err, failure) {
				t.Fatal("sticky close exception hidden", err)
			}
		}
	}
	if c.closeErr != failure || c.fileClosed || c.rootClosed || c.complete || len(c.owner.scope.issued) != 128 || !c.owner.scope.pending {
		t.Fatal("uncertain close replayed or lost custody")
	}
}
