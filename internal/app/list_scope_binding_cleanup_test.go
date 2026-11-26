package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// Actual App/Gate/Store/Scope/compilation, explicit retained physics model.
func TestListScopeCleanupRetainsOriginalLANWithoutRevivingForwardSelection(t *testing.T) {
	a, b, m := listScopeFixture(t, "segment", false)
	var original *dataplane.LANPolicyRuntimePlan
	var cleanup *operationgate.ExclusiveCleanupReview
	listScopeOperation(t, a, func(ctx context.Context) {
		c := listScopeCompilation(t, ctx, a, b)
		if err := b.BindCompilation(ctx, c); err != nil {
			t.Fatal(err)
		}
		original = c.LAN()
		var err error
		cleanup, err = a.Operations.ReviewExclusiveCleanup(ctx)
		if err != nil {
			t.Fatal(err)
		}
		b.verifyCleanupPhysical = func(context.Context) error { return m.verifyErr }
		if err := a.Store.UpdateService("listed", config.ServiceState{Enabled: true, Route: "xray"}); err != nil {
			t.Fatal(err)
		}
		if err := b.ScopeCheck(ctx, original); err == nil {
			t.Fatal("ordinary edit retained forward scope")
		}
		bounded, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := cleanup.WithCurrent(bounded, func() error { return b.cleanupScopeCheck(bounded, original) }); err != nil {
			t.Fatal("unchanged original physical owner lost cleanup read", err)
		}
		wrong := dataplane.CloneLANPolicyRuntime(original)
		wrong.Generation = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		if err := b.cleanupScopeCheck(bounded, wrong); err == nil {
			t.Fatal("foreign LAN accepted")
		}
		m.verifyErr = physicalscope.ErrUnknown
		if err := b.cleanupScopeCheck(bounded, original); !errors.Is(err, physicalscope.ErrUnknown) {
			t.Fatal("physical refusal waived", err)
		}
		if err := b.ScopeCheck(ctx, original); err == nil {
			t.Fatal("cleanup comparison revived forward scope")
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := cleanup.WithCurrent(ctx, func() error { return b.cleanupScopeCheck(ctx, original) }); err == nil {
		t.Fatal("released operation revived")
	}
}
