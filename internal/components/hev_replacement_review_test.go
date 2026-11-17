//go:build linux

package components

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func hevReplacementAdmission(ctx context.Context, effect func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return effect()
}
func hevReplacementImages(t *testing.T, m *Manager) map[string]restorejournal.Image {
	t.Helper()
	s, err := m.openHEVRelease(false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	out := map[string]restorejournal.Image{}
	for _, id := range hevReplacementOrder {
		out[id], err = s.files[id].Read(context.Background())
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}
func hevAssertReplacementImages(t *testing.T, m *Manager, want map[string]restorejournal.Image) {
	t.Helper()
	got := hevReplacementImages(t, m)
	for _, id := range hevReplacementOrder {
		if !sameHEVImage(got[id], want[id]) {
			t.Fatal("original triple not restored", id)
		}
	}
}
func TestHEVReplacementCursorAndCompensation(t *testing.T) {
	for _, fault := range []string{"", "hev:before:a_binary", "hev:after:a_binary", "hev:before:b_receipt", "hev:after:b_receipt", "hev:before:c_lifecycle", "hev:after:c_lifecycle"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			m, spec, info := hevReleaseFixture(t)
			old := []byte("original owned HEV bytes")
			next := []byte("new reviewed HEV bytes")
			if _, err := m.installHEVImage(ctx, spec, info, old); err != nil {
				t.Fatal(err)
			}
			original := hevReplacementImages(t, m)
			if _, err := m.installHEVImageGuarded(ctx, spec, info, next, hevReplacementAdmission, hevReplacementAdmission); err == nil {
				t.Fatal("ordinary entry acquired replacement authority")
			}
			processImage := filepath.Join(t.TempDir(), "original-image")
			if err := os.WriteFile(processImage, old, 0500); err != nil {
				t.Fatal(err)
			}
			desiredProcessImage := filepath.Join(t.TempDir(), "desired-image")
			if err := os.WriteFile(desiredProcessImage, next, 0500); err != nil {
				t.Fatal(err)
			}
			calls := 0
			var retained *HEVReplacementReview
			var privateOld []byte
			inactive := func(c context.Context, r *HEVReplacementReview) error {
				calls++
				retained = r
				privateOld = r.old.Data
				if !r.OwnedBy(m) || r.OwnedBy(New()) {
					t.Fatal("owner binding")
				}
				if err := r.Current(c); err != nil {
					return err
				}
				matched, err := r.MatchesProcessImage(c, processImage)
				if err != nil || !matched {
					t.Fatalf("original image lost after CAS %v %v", matched, err)
				}
				matched, err = r.MatchesProcessImage(c, desiredProcessImage)
				if err != nil || !matched {
					t.Fatal("desired process image missed across CAS", matched, err)
				}
				return nil
			}
			fired := false
			m.updateFault = func(point string) error {
				if fault != "" && point == fault && !fired {
					fired = true
					return errors.New("injected forward failure")
				}
				return nil
			}
			result, err := m.installHEVImageWithReplacement(ctx, spec, info, next, hevReplacementAdmission, inactive, hevReplacementAdmission)
			if fault == "" {
				if err != nil || !result.OK || calls != 7 {
					t.Fatal(result, err, calls)
				}
				hevAssertPair(t, m, next)
			} else {
				if err == nil || !fired || result.OK {
					t.Fatal("failure hidden", result, err)
				}
				hevAssertReplacementImages(t, m, original)
				if err := m.hevReleaseIdle(); err != nil {
					t.Fatal(err)
				}
			}
			if retained == nil || retained.OwnedBy(m) || retained.Current(ctx) == nil {
				t.Fatal("retained closed review")
			}
			if !bytes.Equal(privateOld, make([]byte, len(privateOld))) {
				t.Fatal("closed old bytes retained")
			}
		})
	}
}
func TestHEVReplacementAdmissionAndCancellation(t *testing.T) {
	for _, cut := range []string{"initial", "after-binary", "rename-canceled"} {
		t.Run(cut, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m, spec, info := hevReleaseFixture(t)
			if _, err := m.installHEVImage(ctx, spec, info, []byte("old")); err != nil {
				t.Fatal(err)
			}
			original := hevReplacementImages(t, m)
			calls := 0
			inactive := func(c context.Context, r *HEVReplacementReview) error {
				calls++
				if cut == "initial" || cut == "after-binary" && calls == 3 {
					return ErrRecoveryAuthority
				}
				return r.Current(c)
			}
			rename := func(c context.Context, effect func() error) error {
				if cut == "rename-canceled" {
					cancel()
				}
				return hevReplacementAdmission(c, effect)
			}
			result, err := m.installHEVImageWithReplacement(ctx, spec, info, []byte("new"), hevReplacementAdmission, inactive, rename)
			if err == nil || result.OK {
				t.Fatal("failed admission accepted")
			}
			hevAssertReplacementImages(t, m, original)
			if err := m.hevReleaseIdle(); err != nil {
				t.Fatal("compensation failed", err)
			}
		})
	}
}
func TestHEVReplacementReviewOriginalVectorAndIdentity(t *testing.T) {
	for _, drift := range []string{"a_binary", "b_receipt", "c_lifecycle", "manager", "session", "copy", "cursor", "canceled", "image"} {
		t.Run(drift, func(t *testing.T) {
			ctx := context.Background()
			m, spec, info := hevReleaseFixture(t)
			old := []byte("old-process-bytes")
			if _, err := m.installHEVImage(ctx, spec, info, old); err != nil {
				t.Fatal(err)
			}
			original := hevReplacementImages(t, m)
			s, err := m.openHEVRelease(false)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			if drift == "a_binary" || drift == "b_receipt" || drift == "c_lifecycle" {
				if err := s.files[drift].CompareAndSwap(ctx, original[drift], restorejournal.Image{Exists: true, Data: []byte("foreign")}); err != nil {
					t.Fatal(err)
				}
				if r, err := newHEVReplacementReview(ctx, m, s, original, restorejournal.Image{Exists: true, Data: []byte("desired-image")}); err == nil || r != nil {
					t.Fatal("constructor adopted new preimage", drift)
				}
				return
			}
			r, err := newHEVReplacementReview(ctx, m, s, original, restorejournal.Image{Exists: true, Data: []byte("desired-image")})
			if err != nil {
				t.Fatal(err)
			}
			switch drift {
			case "manager":
				m.StateDir += "-foreign"
				if r.OwnedBy(m) || r.Current(ctx) == nil {
					t.Fatal("manager rebound")
				}
			case "session":
				r.session = &hevReleaseSession{owner: m, replacement: r}
				if r.OwnedBy(m) || r.Current(ctx) == nil {
					t.Fatal("session rebound")
				}
			case "copy":
				copy := &HEVReplacementReview{self: r, manager: m, session: s}
				if copy.OwnedBy(m) || copy.Current(ctx) == nil {
					t.Fatal("copy accepted")
				}
			case "cursor":
				if r.acknowledge("b_receipt", original["b_receipt"], original["b_receipt"], nil) == nil || r.Current(ctx) == nil {
					t.Fatal("out-of-order acknowledgment")
				}
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				if !errors.Is(r.Current(c), context.Canceled) {
					t.Fatal("cancellation ignored")
				}
			case "image":
				p := filepath.Join(t.TempDir(), "foreign")
				if err := os.WriteFile(p, bytes.Repeat([]byte{'x'}, len(old)), 0500); err != nil {
					t.Fatal(err)
				}
				if yes, err := r.MatchesProcessImage(ctx, p); err != nil || yes {
					t.Fatal("foreign process bytes matched", err)
				}
			}
		})
	}
}

func TestHEVReplacementCrashRecoveryAndPendingRefusal(t *testing.T) {
	if root := os.Getenv("RAZVILKA_HEV_REPLACEMENT_CRASH_CHILD"); root != "" {
		m := New()
		m.StateDir = filepath.Join(root, "state")
		m.BinDir = filepath.Join(root, "bin")
		m.Arch = "amd64"
		spec, _ := lookup("hev-socks5-tunnel")
		info, _ := hevPinnedRelease(spec, "amd64")
		m.updateFault = func(phase string) error {
			if phase == os.Getenv("RAZVILKA_HEV_REPLACEMENT_CRASH_PHASE") {
				os.Exit(91)
			}
			return nil
		}
		_, _ = m.installHEVImageWithReplacement(context.Background(), spec, info, []byte("next-owned-image"), hevReplacementAdmission, func(c context.Context, r *HEVReplacementReview) error { return r.Current(c) }, hevReplacementAdmission)
		os.Exit(92)
	}
	for _, phase := range []string{"hev:after:a_binary", "hev:after:b_receipt", "hev:after:c_lifecycle"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			m, spec, info := hevReleaseFixture(t)
			if _, err := m.installHEVImage(ctx, spec, info, []byte("original-owned-image")); err != nil {
				t.Fatal(err)
			}
			original := hevReplacementImages(t, m)
			childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestHEVReplacementCrashRecoveryAndPendingRefusal$")
			cmd.Env = append(os.Environ(), "RAZVILKA_HEV_REPLACEMENT_CRASH_CHILD="+filepath.Dir(m.StateDir), "RAZVILKA_HEV_REPLACEMENT_CRASH_PHASE="+phase)
			err := cmd.Run()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 91 {
				t.Fatalf("child missed durable cut: %v", err)
			}
			if err := m.hevReleaseIdle(); err == nil {
				t.Fatal("pending crash admitted")
			}
			partial := hevReplacementImages(t, m)
			if _, err := m.installHEVImageWithReplacement(ctx, spec, info, []byte("other-new-image"), hevReplacementAdmission, func(context.Context, *HEVReplacementReview) error {
				t.Fatal("pending admitted inactivity callback")
				return nil
			}, hevReplacementAdmission); err == nil {
				t.Fatal("replacement silently recovered pending journal")
			}
			hevAssertReplacementImages(t, m, partial)
			fresh := New()
			fresh.StateDir = m.StateDir
			fresh.BinDir = m.BinDir
			fresh.Arch = "amd64"
			if out, err := fresh.RecoverHEVRelease(ctx); err != nil || out != restorejournal.RolledBack {
				t.Fatal(out, err)
			}
			hevAssertReplacementImages(t, fresh, original)
			if out, err := fresh.RecoverHEVRelease(ctx); err != nil || out != restorejournal.Clean {
				t.Fatal(out, err)
			}
		})
	}
}
