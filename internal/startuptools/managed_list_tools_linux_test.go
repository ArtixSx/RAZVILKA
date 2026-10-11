//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestManagedListCaptureHoldsBothMissingAliasesAndDetectsAppearance(t *testing.T) {
	for _, changed := range []int{0, 1} {
		dir, r := rootReviewFixture(t)
		r.profile.wgEngine = managedListWGProfile
		r.profile.wgAliases = [2]string{filepath.Join(dir, "bin", "wg"), filepath.Join(dir, "sbin", "awg")}
		if err := r.captureWG(context.Background()); err != nil {
			t.Fatal("optional primary/secondary absence refused", err)
		}
		for i, alias := range r.profile.wgAliases {
			if r.wgEntry[i] != nil || !r.absent[alias] || !r.absent[filepath.Dir(alias)] {
				t.Fatal("missing entry or its absent parent was not captured", i)
			}
		}
		if err := r.pathsCurrent(context.Background()); err != nil {
			t.Fatal(err)
		}
		path := r.profile.wgAliases[changed]
		if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("new unreviewed executable"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := r.pathsCurrent(context.Background()); err == nil {
			t.Fatal("new missing-path occupant preserved original Linux closure")
		}
	}
}

func TestManagedListCaptureRejectsPresentInvalidImageAndStrictPrimaryAbsence(t *testing.T) {
	for _, present := range []int{0, 1} {
		dir, r := rootReviewFixture(t)
		r.profile.wgEngine = managedListWGProfile
		r.profile.wgAliases = [2]string{filepath.Join(dir, "wg"), filepath.Join(dir, "awg")}
		if err := os.WriteFile(r.profile.wgAliases[present], []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := r.captureWG(context.Background()); err == nil {
			t.Fatal("present invalid optional tool was treated as absent or PATH fallback", present)
		}
	}
	for _, engine := range []string{"wireguard", "amneziawg"} {
		dir, r := rootReviewFixture(t)
		r.profile.wgEngine = engine
		r.profile.wgAliases = [2]string{filepath.Join(dir, "wg"), filepath.Join(dir, "awg")}
		if err := r.captureWG(context.Background()); err == nil {
			t.Fatal("strict engine-specific factory accepted missing primary", engine)
		}
	}
}
