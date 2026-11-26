package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestListScopeWGOperationBindingOriginalCleanupAndRevocation(t *testing.T) {
	a, b, physics := listScopeFixture(t, "segment", false)
	a.Dataplane = dataplane.New(t.TempDir())
	listScopeOperation(t, a, func(ctx context.Context) {
		compilation := listScopeCompilation(t, ctx, a, b)
		if err := b.BindCompilation(ctx, compilation); err != nil {
			t.Fatal(err)
		}
		// Same fixture's explicitly modeled retained physics; all App/Store/
		// Gate/control/compilation owners below are genuine.
		b.verifyCleanupPhysical = func(context.Context) error { return physics.verifyErr }
		binding, err := a.reviewListWGOperation(ctx, b)
		if err != nil {
			t.Fatal(err)
		}
		defer binding.close()
		bound, err := binding.context(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Store.UpdateService("listed", config.ServiceState{Enabled: true, Route: "xray"}); err != nil {
			t.Fatal(err)
		}
		if _, err := binding.context(ctx); err == nil {
			t.Fatal("ordinary edit renewed forward binding")
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(bound), time.Second)
		defer cancel()
		calls := 0
		if err := binding.withCleanup(cleanup, compilation.LAN(), func(context.Context) error { calls++; return nil }); err != nil || calls != 1 {
			t.Fatal("original retained cleanup", err, calls)
		}
		wrong := compilation.LAN()
		wrong.Generation = strings.Repeat("f", 64)
		if err := binding.withCleanup(cleanup, wrong, func(context.Context) error { calls++; return nil }); err == nil || calls != 1 {
			t.Fatal("foreign LAN cleanup", err, calls)
		}
		physics.verifyErr = errors.New("retained physical incarnation changed")
		if err := binding.withCleanup(cleanup, compilation.LAN(), func(context.Context) error { calls++; return nil }); err == nil || calls != 1 {
			t.Fatal("changed physical cleanup", err, calls)
		}
		if err := binding.close(); err != nil {
			t.Fatal(err)
		}
		if err := binding.withCleanup(cleanup, compilation.LAN(), func(context.Context) error { calls++; return nil }); err == nil || calls != 1 {
			t.Fatal("closed binding", err, calls)
		}
	})
}
