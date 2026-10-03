//go:build linux

package selfupdatejournal

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestNativeSelfUpdateFileReplacementStopAtActualRename(t *testing.T) {
	f := fixtureAt(t, t.TempDir())
	f.prepare(t)
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "control")
	authority, err := operationgate.InitializeSelfUpdateControl(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	admission := func(c context.Context, effect string, begin func() error) error {
		calls++
		if _, err := operationgate.RequestSelfUpdateStop(c, root, transaction, 7); err != nil {
			return err
		}
		return operationgate.WithSelfUpdateEffectAdmission(c, root, transaction, authority.InstallationID, authority.Sequence, effect, begin)
	}
	if err := f.store.InstallAdmitted(ctx, transaction, okay, okay, admission); !errors.Is(err, operationgate.ErrSelfUpdateStopped) || calls != 1 {
		t.Fatal("actual rename bypassed durable Stop", err, calls)
	}
	f.old(t)
	f.reopen(t)
	if err := f.store.InstallAdmitted(ctx, transaction, okay, okay, admission); !errors.Is(err, operationgate.ErrSelfUpdateStopped) {
		t.Fatal("restart cleared Stop", err)
	}
	f.old(t)
}
