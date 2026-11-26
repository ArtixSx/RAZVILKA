package config

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func serviceModeReceiptFixture(t *testing.T) (*Store, context.Context) {
	t.Helper()
	s, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	mode := "manual"
	if err := s.UpdateServiceControl(&mode, nil, s.Get().Revision); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return s, ctx
}

func TestServiceModeActualWriterReceiptIsExactOneUseAndOriginalUndo(t *testing.T) {
	s, ctx := serviceModeReceiptFixture(t)
	before := s.Get()
	undo, receipt, err := s.UpdateManualToAutoReviewed(ctx, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	from, to, err := receipt.CommittedImages(ctx)
	want := cloneConfig(before)
	want.ServiceControl.Mode, want.Revision = "auto", before.Revision+1
	if err != nil || !receipt.MatchesStore(s) || !receipt.PendingAcceptance() || !reflect.DeepEqual(from, before) || !reflect.DeepEqual(to, want) || !reflect.DeepEqual(s.Get(), want) {
		t.Fatal("actual mode-only receipt/image", err)
	}
	if err := receipt.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	if receipt.PendingAcceptance() || receipt.Accept(ctx) == nil {
		t.Fatal("receipt accepted twice")
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	restoredFrom, restoredTo, err := receipt.RestoredImages(ctx)
	if err != nil || !reflect.DeepEqual(restoredFrom, want) || !reflect.DeepEqual(restoredTo, before) || !reflect.DeepEqual(s.Get(), before) {
		t.Fatal("actual original undo was not proven", err)
	}
	if _, _, err := receipt.CommittedImages(ctx); err == nil {
		t.Fatal("restored receipt revived committed phase")
	}
	if err := undo(); err != nil {
		t.Fatal("joined original undo was not idempotent", err)
	}
}

func TestServiceModeReceiptRefusesCopiesForeignStoreAndFullImageDrift(t *testing.T) {
	s, ctx := serviceModeReceiptFixture(t)
	_, receipt, err := s.UpdateManualToAutoReviewed(ctx, s.Get().Revision)
	if err != nil {
		t.Fatal(err)
	}
	copy := &ServiceModeCommitReview{self: receipt.self, store: receipt.store, before: receipt.before, after: receipt.after}
	copy.phase.Store(serviceModeCommitted)
	for _, invalid := range []*ServiceModeCommitReview{nil, {}, copy} {
		if invalid.MatchesStore(s) || invalid.PendingAcceptance() {
			t.Fatal("unissued/copied receipt accepted")
		}
		if _, _, err := invalid.CommittedImages(ctx); err == nil {
			t.Fatal("unissued/copied image accepted")
		}
	}
	foreign, _ := serviceModeReceiptFixture(t)
	if receipt.MatchesStore(foreign) {
		t.Fatal("same config on another Store adopted")
	}
	if err := s.SetSafeMode(true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := receipt.CommittedImages(ctx); err == nil || receipt.Accept(ctx) == nil {
		t.Fatal("changed complete image accepted")
	}
}

func TestServiceModeOriginalUndoRefusesAnotherActualWriter(t *testing.T) {
	s, ctx := serviceModeReceiptFixture(t)
	undo, receipt, err := s.UpdateManualToAutoReviewed(ctx, s.Get().Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSafeMode(true); err != nil {
		t.Fatal(err)
	}
	changed := s.Get()
	if undo() == nil || !reflect.DeepEqual(s.Get(), changed) {
		t.Fatal("undo overwrote another actual writer")
	}
	if _, _, err := receipt.RestoredImages(ctx); err == nil {
		t.Fatal("failed undo fabricated restored phase")
	}
}

func TestServiceModeWriterRefusesBroaderPermissionsCancellationAndUnknownStore(t *testing.T) {
	for _, change := range []string{"safe-mode", "stopped", "already-auto", "stale-revision", "canceled", "unknown-store"} {
		t.Run(change, func(t *testing.T) {
			s, ctx := serviceModeReceiptFixture(t)
			revision := s.Get().Revision
			switch change {
			case "safe-mode":
				if err := s.SetSafeMode(true); err != nil {
					t.Fatal(err)
				}
				revision = s.Get().Revision
			case "stopped":
				s.mu.Lock()
				s.cfg.ServiceControl.Stopped = true
				err := s.saveLocked()
				s.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			case "already-auto":
				mode := "auto"
				if err := s.UpdateServiceControl(&mode, nil, revision); err != nil {
					t.Fatal(err)
				}
				revision = s.Get().Revision
			case "stale-revision":
				revision--
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "unknown-store":
				s.mu.Lock()
				s.writeUncertain = true
				s.mu.Unlock() // Explicit unknown-write model, no successful CAS fabricated.
			}
			before := s.Get()
			undo, receipt, err := s.UpdateManualToAutoReviewed(ctx, revision)
			if err == nil || undo != nil || receipt != nil || !reflect.DeepEqual(s.Get(), before) {
				t.Fatal("refusal changed memory or issued a writer receipt", err)
			}
			if change == "unknown-store" && !errors.Is(err, restorejournal.ErrRecovery) {
				t.Fatal("unknown write lost recovery cause", err)
			}
		})
	}
}
