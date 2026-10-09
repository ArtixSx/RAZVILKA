//go:build linux

package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNativePairedOfflineRestoreRefusesUnreviewedWriterBeforeOwnerOrEffect(t *testing.T) {
	f := pairedReaderSetup(t)
	calls := 0
	f.adapter.runtimeInactive = func(context.Context, string) error { calls++; return nil }
	owner := func(context.Context, string) error { calls++; return nil }
	admit := func(context.Context, string, string, func() error) error { calls++; return nil }
	result, err := f.adapter.RestorePairedPriorState(f.ctx, f.review.ID, owner, admit)
	// The running test ELF is physically different from this fixture's bound
	// release candidate. A reported version/path/owner callback cannot admit it.
	if !errors.Is(err, ErrPairedOfflineRestore) || result.State != "" || calls != 0 {
		t.Fatal("unreviewed restore writer reached authority/effects", err, result, calls)
	}
}

// Real fd-pinned Linux exchanges with streamed source bytes. Process/runtime
// owners are modeled here; Root's CLI acceptance must exercise those separately.
func TestNativePairedOfflineRestorePublishesGuardsBeforeOldExecutable(t *testing.T) {
	f, receipt := offlineRestoreFixture(t, true)
	var order []string
	check := func(ctx context.Context) error {
		if ctx != f.ctx {
			return ErrPairedOfflineRestore
		}
		return ctx.Err()
	}
	err := restorePairedOffline(f.ctx, f.installation, receipt, func(string) error { return nil }, check, func(effect string, begin func() error) error { return begin() }, commitOfflinePriorReplacement, func(stage string) error {
		if stage == "before:offline-replace:bin/razvilka" {
			for _, name := range []string{"S99razvilka", "S99artem-flow"} {
				data, err := os.ReadFile(filepath.Join(f.installation, "etc/init.d", name))
				if err != nil || string(data) != pairedOfflineInitGuard {
					t.Fatal("old executable reached unguarded init", name, err)
				}
			}
		}
		order = append(order, stage)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if order[len(order)-1] != "after:offline-restore" {
		t.Fatal("restore did not complete", order)
	}
	info, err := os.Stat(filepath.Join(f.installation, "etc/init.d/S99razvilka"))
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("guard is not executable", err)
	}
}
