//go:build linux

package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestMihomoRecoveryReviewedRefusesAnotherActualTransaction(t *testing.T) {
	m, info := mihomoReleaseFixture(t)
	pending := func(data []byte) MihomoReleaseRecoveryReview {
		t.Helper()
		image := mihomoFixtureStage(t, m, data)
		rollback := false
		m.updateFault = func(phase string) error {
			if phase == "mihomo:after:a_binary" {
				rollback = true
				return errors.New("modeled forward failure")
			}
			if rollback && phase == "mihomo:before:a_binary" {
				return errors.New("modeled uncertain undo")
			}
			return nil
		}
		if _, err := m.installMihomoImage(context.Background(), info, image, mihomoFixtureAdmission, mihomoFixtureAdmission); !errors.Is(err, restorejournal.ErrRecovery) {
			t.Fatal("missing retained uncertain transaction", err)
		}
		review, err := m.InspectMihomoReleaseRecovery(context.Background())
		if err != nil || !review.Pending || len(review.Identity) != 64 {
			t.Fatal(review, err)
		}
		m.updateFault = nil
		return review
	}
	first := pending([]byte("first artifact"))
	if out, err := m.RecoverMihomoReleaseReviewed(context.Background(), first.Identity); out != restorejournal.RolledBack || err != nil {
		t.Fatal(out, err)
	}
	second := pending([]byte("second artifact"))
	if second.Identity == first.Identity {
		t.Fatal("new transaction reused old review")
	}
	if out, err := m.RecoverMihomoReleaseReviewed(context.Background(), first.Identity); out != restorejournal.Blocked || !errors.Is(err, restorejournal.ErrConflict) {
		t.Fatal("old review changed new transaction", out, err)
	}
	if got, err := os.ReadFile(filepath.Join(m.BinDir, "mihomo")); err != nil || string(got) != "second artifact" {
		t.Fatal("stale review mutated target", err)
	}
	if out, err := m.RecoverMihomoReleaseReviewed(context.Background(), second.Identity); out != restorejournal.RolledBack || err != nil {
		t.Fatal(out, err)
	}
}
