package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStrategyStateAdmissionPreservesEveryExistingState(t *testing.T) {
	for _, content := range []string{`{"schema_version":1}`, `{"schema_version":4}`, `{"schema_version":5,"compatibility_finalizing":true}`, `{"schema_version":2}`, `{"schema_version":`} {
		t.Run(content, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "strategy-lab.json")
			if err := requireNoStrategyState(context.Background(), root); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if err := requireNoStrategyState(context.Background(), root); !errors.Is(err, ErrStrategyStateAdmission) {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != content {
				t.Fatal("state changed", err)
			}
		})
	}
}

func TestLateStrategyStateBlocksControllerReplacement(t *testing.T) {
	a, _, review := fileAdapterFixture(t)
	ctx := context.Background()
	if err := a.AuthorityAction(ctx, review.ID, review.Revision, "start/live"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(a.installation, "razvilka", "state", "strategy-lab.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":5}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.Ready(ctx, review.ID); !errors.Is(err, ErrStrategyStateAdmission) {
		t.Fatal("ready accepted late state", err)
	}
	if _, err := a.stageFileReviewProducer(ctx, updateRecord{}, nil, nil, nil); !errors.Is(err, ErrStrategyStateAdmission) {
		t.Fatal("preparation accepted state before authority", err)
	}
	for _, action := range []string{"start/live", "replace-to-rollback", bootstrapOfflineAction} {
		if err := a.AuthorityAction(ctx, review.ID, review.Revision, action); !errors.Is(err, ErrStrategyStateAdmission) {
			t.Fatalf("%s: %v", action, err)
		}
	}
	if err := a.AuthorityAction(ctx, review.ID, review.Revision, "stop-owned"); err != nil {
		t.Fatal("owned cleanup blocked", err)
	}
}

func TestStrategyStateAdmissionUnsafeObjectsAndCancellation(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "strategy-lab.json")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := requireNoStrategyState(context.Background(), root); !errors.Is(err, ErrStrategyStateAdmission) {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "absent"), path); err == nil {
		if err := requireNoStrategyState(context.Background(), root); !errors.Is(err, ErrStrategyStateAdmission) {
			t.Fatal("dangling symlink accepted", err)
		}
	} else {
		t.Log("symlink unavailable", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := requireNoStrategyState(ctx, root); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestStrategyStateCustomAbsentPathRefusesApply(t *testing.T) {
	u := readyUpdater(t)
	u.StrategyLabStatePath = filepath.Join(t.TempDir(), "custom-absent.json")
	if _, err := os.Lstat(u.StrategyLabStatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fixture must be absent", err)
	}
	job := u.Snapshot()
	if _, err := u.Apply(context.Background(), job.ID, job.ReviewToken, job.ConfigRevision, "fixture"); !errors.Is(err, ErrStrategyStateAdmission) {
		t.Fatal("custom absent state path admitted", err)
	}
}

func TestStrategyStateFailureClassifierDoesNotGrantEffects(t *testing.T) {
	for _, stage := range []string{"metadata", "preflight"} {
		if !knownPreparationFailure("failed", stage, "strategy-state-pair-required") {
			t.Fatal(stage)
		}
	}
	for _, stage := range []string{"downloading", "verifying", "installing", "restarting"} {
		if knownPreparationFailure("failed", stage, "strategy-state-pair-required") {
			t.Fatal(stage)
		}
	}
}
