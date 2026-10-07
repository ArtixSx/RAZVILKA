//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func rootReviewFixture(t *testing.T) (string, *heldReview) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("protected filesystem regressions require Root")
	}
	if info, err := os.Stat("/root"); err != nil || !info.IsDir() {
		t.Skip("protected Root scratch directory unavailable")
	}
	dir, err := os.MkdirTemp("/root", "razvilka-startuptools-")
	if err != nil {
		t.Fatal(err)
	}
	r := &heldReview{profile: profile{arch: runtime.GOARCH, libraries: []string{dir}}, images: map[string]*heldImage{}, nodes: map[string]heldNode{}, absent: map[string]bool{}, roles: map[string]map[imageRole]bool{}, directories: []string{dir}}
	t.Cleanup(func() { _ = r.close(); _ = os.RemoveAll(dir) })
	return dir, r
}

func TestProtectedResolutionChecksIntermediateBeforeDotDot(t *testing.T) {
	dir, r := rootReviewFixture(t)
	unsafe := filepath.Join(dir, "unsafe")
	if err := os.Mkdir(unsafe, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "good"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink("unsafe/../good", alias); err != nil {
		t.Fatal(err)
	}
	if _, err := r.resolve(alias); err == nil {
		t.Fatal("normalizing dot-dot hid a writable intermediate directory")
	}
}

func TestHeldDependencyDoesNotSkipLaterEntryRole(t *testing.T) {
	dir, r := rootReviewFixture(t)
	raw := elfFixture("/lib/nonexistent-standalone-dso-interpreter", nil)
	if runtime.GOARCH == "amd64" {
		binary.LittleEndian.PutUint16(raw[18:], 62)
	}
	path := filepath.Join(dir, "dependency.so")
	if err := os.WriteFile(path, raw, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := r.image(context.Background(), path, dependencyRole); err != nil {
		t.Fatal("DSO standalone interpreter was treated as a loaded dependency", err)
	}
	// The cached DSO still cannot be executed: its interpreter differs from
	// the reviewed entry loader, despite identical file identity and bytes.
	r.profile.loader = "/opt/lib/reviewed-entry-loader"
	if _, err := r.image(context.Background(), path, entryRole); err == nil {
		t.Fatal("cached DSO skipped exact entry-role interpreter validation")
	}
}

func TestHeldPathsRejectIdenticalReplacementAndNewSearchOccupant(t *testing.T) {
	dir, r := rootReviewFixture(t)
	path := filepath.Join(dir, "image")
	if err := os.WriteFile(path, []byte("identical bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.resolve(path); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("identical bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := r.pathsCurrent(context.Background()); err == nil {
		t.Fatal("same-content replacement preserved held path identity")
	}
	_, clean := rootReviewFixture(t)
	missing := filepath.Join(clean.profile.libraries[0], "absent-library.so")
	if err := clean.missing(missing); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(missing, []byte("new search occupant"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := clean.pathsCurrent(context.Background()); err == nil {
		t.Fatal("new earlier search candidate escaped the retained closure")
	}
}

func TestStockNameInputsRequireHeldAbsenceAndRejectNewDatabase(t *testing.T) {
	dir, r := rootReviewFixture(t)
	if err := r.captureStockNameAbsence(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	if len(r.absent) != 8 {
		t.Fatal("incomplete stock name input coverage", len(r.absent))
	}
	if err := os.WriteFile(filepath.Join(dir, "rt_tables"), []byte("201 named\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.pathsCurrent(context.Background()); err == nil {
		t.Fatal("new DB changed numeric semantics without revoking review")
	}
	if err := r.captureStockNameAbsence(context.Background(), dir); err == nil {
		t.Fatal("existing DB was silently ignored")
	}
}
