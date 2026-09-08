package engineconfig

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

type injectedTarget struct {
	restorejournal.Target
	write func(restorejournal.Target, context.Context, restorejournal.Image, restorejournal.Image) error
}

func (t injectedTarget) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	return t.write(t.Target, ctx, before, after)
}

func TestStageRollbackFailuresAreNotHidden(t *testing.T) {
	for _, mode := range []string{"restore-existing", "remove-new", "failed-write-committed", "rollback-write-failure", "rollback-remove-failure", "rollback-error-after-commit"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			m := New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
			first := m.stagePath("nfqws2", "exclude-list")
			existed := mode == "restore-existing" || mode == "rollback-write-failure" || mode == "rollback-error-after-commit"
			if existed {
				if _, err := m.Stage("nfqws2", "exclude-list", "before.example\n"); err != nil {
					t.Fatal(err)
				}
			}
			writes := 0
			wrap := func(_ string, target restorejournal.Target) restorejournal.Target {
				return injectedTarget{Target: target, write: func(inner restorejournal.Target, ctx context.Context, before, after restorejournal.Image) error {
					writes++
					if writes == 2 {
						if mode == "failed-write-committed" {
							if err := inner.CompareAndSwap(ctx, before, after); err != nil {
								return err
							}
						}
						return restorejournal.ErrRecovery
					}
					if writes == 3 && (mode == "rollback-write-failure" || mode == "rollback-remove-failure") {
						return restorejournal.ErrRecovery
					}
					if err := inner.CompareAndSwap(ctx, before, after); err != nil {
						return err
					}
					if writes == 3 && mode == "rollback-error-after-commit" {
						return restorejournal.ErrRecovery
					}
					return nil
				}}
			}
			_, _, err := m.stageBatch([]StageItem{{EngineID: "nfqws2", FileID: "exclude-list", Content: "new.example\n"}, {EngineID: "nfqws2", FileID: "user-list", Content: "second.example\n"}}, ValidatePrivateContent, wrap)
			if err == nil {
				t.Fatal("write failure ignored")
			}
			incomplete := mode == "rollback-write-failure" || mode == "rollback-remove-failure"
			if errors.Is(err, ErrStageRollback) != incomplete {
				t.Fatalf("wrong classification: %v", err)
			}
			if strings.Contains(err.Error(), root) {
				t.Fatal("private path leaked")
			}
			data, readErr := os.ReadFile(first)
			switch {
			case incomplete:
				if readErr != nil || string(data) != "new.example\n" {
					t.Fatal("unexpected incomplete state")
				}
			case existed:
				if readErr != nil || string(data) != "before.example\n" {
					t.Fatal("before image lost")
				}
			default:
				if !errors.Is(readErr, os.ErrNotExist) {
					t.Fatal("new draft not removed")
				}
			}
			if _, err := os.Stat(m.stagePath("nfqws2", "user-list")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed target left committed")
			}
		})
	}
}

func TestStagePreparationFailureWritesNoDraft(t *testing.T) {
	root := t.TempDir()
	m := New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
	if _, err := m.Stage("nfqws2", "user-list", "before.example\n"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.StageRoot, "sing-box"), []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.StagePrivate([]StageItem{{EngineID: "nfqws2", FileID: "user-list", Content: "after.example\n"}, {EngineID: "sing-box", FileID: "main", Content: "{}"}}); err == nil {
		t.Fatal("invalid target parent accepted")
	}
	got, err := m.Read("nfqws2", "user-list")
	if err != nil || got.Content != "before.example\n" {
		t.Fatal("earlier draft changed during preparation")
	}
}
