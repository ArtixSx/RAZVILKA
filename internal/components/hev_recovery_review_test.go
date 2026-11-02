package components

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHEVRecoveryReviewMissingIsInert(t *testing.T) {
	m, _, _ := hevReleaseFixture(t)
	review, err := m.InspectHEVReleaseRecovery(context.Background())
	if err != nil || review.Pending || review.Identity != "" {
		t.Fatal(review, err)
	}
	if _, err := os.Stat(m.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("GET initialized component state", err)
	}
}

func TestHEVRecoveryReviewedRefusesAnotherActualTransaction(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("actual original existing writer ownership requires Linux")
	}
	m, spec, info := hevReleaseFixture(t)
	pending := func(data []byte) HEVReleaseRecoveryReview {
		t.Helper()
		rollback := false
		m.updateFault = func(phase string) error {
			if phase == "hev:after:a_binary" {
				rollback = true
				return errors.New("modeled forward failure")
			}
			if rollback && phase == "hev:before:a_binary" {
				return errors.New("modeled uncertain undo")
			}
			return nil
		}
		if _, err := m.installHEVImage(context.Background(), spec, info, data); !errors.Is(err, restorejournal.ErrRecovery) {
			t.Fatal("no retained pending transaction", err)
		}
		review, err := m.InspectHEVReleaseRecovery(context.Background())
		if err != nil || !review.Pending || len(review.Identity) != 64 {
			t.Fatal(review, err)
		}
		m.updateFault = nil
		return review
	}
	first := pending([]byte("model first"))
	if out, err := m.RecoverHEVReleaseReviewed(context.Background(), first.Identity); out != restorejournal.RolledBack || err != nil {
		t.Fatal(out, err)
	}
	second := pending([]byte("model second"))
	if second.Identity == first.Identity {
		t.Fatal("distinct actual journal reused stale identity")
	}
	if out, err := m.RecoverHEVReleaseReviewed(context.Background(), first.Identity); out != restorejournal.Blocked || !errors.Is(err, restorejournal.ErrConflict) {
		t.Fatal("stale panel request undid different transaction", out, err)
	}
	got, err := os.ReadFile(filepath.Join(m.BinDir, spec.Binary))
	if err != nil || string(got) != "model second" {
		t.Fatal("stale review changed target", err)
	}
	if out, err := m.RecoverHEVReleaseReviewed(context.Background(), second.Identity); out != restorejournal.RolledBack || err != nil {
		t.Fatal(out, err)
	}
	hevAssertPair(t, m, nil)
}
