//go:build linux

package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishInitialUSQUERequiresCurrentPermitAndAbsentTarget(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "usque")
	payload := []byte("reviewed binary bytes")
	permit := func(context.Context) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := publishInitialUSQUE(ctx, target, payload, context.Context.Err); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrNoMutation) {
		t.Fatalf("canceled publication: %v", err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("canceled staging left entries: %v %v", entries, err)
	}
	if err := publishInitialUSQUE(context.Background(), target, payload, permit); err != nil {
		t.Fatal(err)
	}
	if err := publishInitialUSQUE(context.Background(), target, []byte("different bytes"), permit); !errors.Is(err, ErrComponentAlreadyInstalled) {
		t.Fatalf("existing target replaced: %v", err)
	}
	info, err := os.Lstat(target)
	if err != nil || info.Mode().Perm() != 0500 {
		t.Fatalf("managed executable mode: %v %v", info, err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != string(payload) {
		t.Fatalf("managed executable changed: %q %v", data, err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Fatalf("publication left staging files: %v %v", entries, err)
	}
	if err := checkInitialUSQUEPublication(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, ".usque-core-interrupted")
	if err := os.Link(target, staged); err != nil {
		t.Fatal(err)
	}
	if err := checkInitialUSQUEPublication(context.Background(), target); !errors.Is(err, ErrUSQUEInstallPending) {
		t.Fatalf("interrupted staging was confirmed: %v", err)
	}
}

func TestPublishInitialUSQUERefusesReplacedRootAndSymlinkTarget(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "owners")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "usque")
	old := filepath.Join(parent, "previous")
	guard := func(context.Context) error {
		if err := os.Rename(dir, old); err != nil {
			return err
		}
		return os.Mkdir(dir, 0700)
	}
	if err := publishInitialUSQUE(context.Background(), target, []byte("reviewed binary"), guard); !errors.Is(err, ErrRecoveryAuthority) {
		t.Fatalf("publication in moved root: %v", err)
	}
	for _, path := range []string{dir, old} {
		if entries, err := os.ReadDir(path); err != nil || len(entries) != 0 {
			t.Fatalf("moved owner left entries: %s %v %v", path, entries, err)
		}
	}
	if err := os.Symlink(filepath.Join(old, "outside"), target); err != nil {
		t.Fatal(err)
	}
	if err := publishInitialUSQUE(context.Background(), target, []byte("reviewed binary"), context.Context.Err); !errors.Is(err, ErrNoMutation) {
		t.Fatalf("symlink publication: %v", err)
	}
	if info, err := os.Lstat(target); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("foreign target was changed: %v %v", info, err)
	}
}
