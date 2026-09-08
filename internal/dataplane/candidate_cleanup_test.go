package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type cancelledCandidate struct{ fakeAdapter }

func (a *cancelledCandidate) Canary(ctx context.Context, _ RoutePlan, root string) error {
	if err := os.WriteFile(filepath.Join(root, "candidate-secret"), []byte("fixture"), 0o600); err != nil {
		return err
	}
	return context.Canceled
}

func TestCandidateCancellationCleansOnlyTemporaryDirectory(t *testing.T) {
	path := t.TempDir()
	manager := New(path)
	adapter := &cancelledCandidate{fakeAdapter: fakeAdapter{id: "sing-box"}}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(path, "live-config")
	if err := os.WriteFile(live, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.ProbeCandidate(context.Background(), Plan{}, adapter.ID()); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(path, "candidate-probes"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("candidate files remain: %v %v", entries, err)
	}
	if data, err := os.ReadFile(live); err != nil || string(data) != "untouched" {
		t.Fatal("live config changed")
	}
	for _, call := range adapter.calls {
		if call == "activate" || call == "commit-adapter" || call == "rollback" {
			t.Fatalf("candidate performed live mutation: %s", call)
		}
	}
}

func TestCandidateRejectsSymlinkCleanupRoot(t *testing.T) {
	path, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(path, "candidate-probes")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	manager := New(path)
	adapter := &cancelledCandidate{fakeAdapter: fakeAdapter{id: "sing-box"}}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	if err := manager.ProbeCandidate(context.Background(), Plan{}, adapter.ID()); err == nil {
		t.Fatal("symlink probe directory accepted")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 || len(adapter.calls) != 0 {
		t.Fatal("candidate touched outside directory")
	}
}
