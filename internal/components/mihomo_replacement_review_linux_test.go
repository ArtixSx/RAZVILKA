//go:build linux

package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// These are actual file/journal/CAS tests with modeled executable bytes. The
// official predecessor fixture separately verifies a real running old image.
func TestMihomoReplacementCursorAndCompensation(t *testing.T) {
	for _, fault := range []string{"", "mihomo:after:a_binary", "mihomo:after:b_receipt", "mihomo:after:c_lifecycle"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			m, info := mihomoReleaseFixture(t)
			oldData := []byte("original older modeled executable\n")
			old := mihomoFixtureStage(t, m, oldData)
			oldInfo := info
			oldInfo.Version = "1.19.32"
			if result, err := m.installMihomoImage(ctx, oldInfo, old, mihomoFixtureAdmission, mihomoFixtureAdmission); err != nil || !result.OK {
				t.Fatal(result, err)
			}
			nextData := []byte("new reviewed modeled executable\n")
			next := mihomoFixtureStage(t, m, nextData)
			if _, err := m.installMihomoImage(ctx, info, next, mihomoFixtureAdmission, mihomoFixtureAdmission); err == nil {
				t.Fatal("old entry silently acquired replacement authority")
			}
			copyPath := filepath.Join(t.TempDir(), "opaque-old-image")
			if err := os.WriteFile(copyPath, oldData, 0500); err != nil {
				t.Fatal(err)
			}
			calls := 0
			var retained *MihomoReplacementReview
			inactive := func(c context.Context, r *MihomoReplacementReview) error {
				calls++
				retained = r
				if !r.OwnedBy(m) || r.OwnedBy(New()) {
					t.Fatal("foreign manager binding")
				}
				if err := r.Current(c); err != nil {
					return err
				}
				match, err := r.MatchesProcessImage(c, copyPath)
				if err != nil || !match {
					t.Fatal("old image disappeared after acknowledged new binary CAS", match, err)
				}
				return nil
			}
			fired := false
			m.updateFault = func(point string) error {
				if point == fault && !fired {
					fired = true
					return errors.New("fixture forward failure")
				}
				return nil
			}
			result, err := m.installMihomoImageWithReplacement(ctx, info, next, mihomoFixtureAdmission, mihomoFixtureAdmission, inactive)
			if fault == "" {
				if err != nil || !result.OK || calls != 7 {
					t.Fatal(result, err, "observations", calls)
				}
				mihomoAssertInstalled(t, m, nextData)
			} else {
				if err == nil || !fired || result.OK {
					t.Fatal("hidden failed update", result, err)
				}
				actual, e := os.ReadFile(filepath.Join(m.BinDir, "mihomo"))
				if e != nil || string(actual) != string(oldData) {
					t.Fatal("old image not compensated", e)
				}
				if e := m.mihomoReleaseIdle(); e != nil {
					t.Fatal("known compensation pending", e)
				}
			}
			if retained == nil || retained.OwnedBy(m) || retained.Current(ctx) == nil {
				t.Fatal("closed writer review survived")
			}
		})
	}
}

func TestMihomoReplacementReviewRejectsCopiedAndUnacknowledgedState(t *testing.T) {
	ctx := context.Background()
	m, info := mihomoReleaseFixture(t)
	old := mihomoFixtureStage(t, m, []byte("old modeled binary"))
	if result, err := m.installMihomoImage(ctx, info, old, mihomoFixtureAdmission, mihomoFixtureAdmission); err != nil || !result.OK {
		t.Fatal(result, err)
	}
	s, err := m.openMihomoRelease(false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	r, err := newMihomoReplacementReview(ctx, m, s, old)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	copy := &MihomoReplacementReview{self: r, manager: m, session: s, root: r.root, old: r.old, ref: r.ref, expected: r.expected}
	if copy.Current(ctx) == nil || copy.OwnedBy(m) {
		t.Fatal("copied writer review accepted")
	}
	if err := os.WriteFile(s.paths["b_receipt"], []byte("third state\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if r.Current(ctx) == nil {
		t.Fatal("unacknowledged receipt image accepted")
	}
}
