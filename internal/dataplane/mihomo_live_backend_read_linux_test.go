//go:build linux

package dataplane

import (
	"context"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Only comparison bindings are assembled here around the real official
// retained child/source and actual registered component adapter. This has no
// COMMON issuer, plan readiness, packet effect or service evidence. The full
// App native scenario separately exercises the genuine live resource issuer.
func testMihomoLiveBackendReadViewBindings(t *testing.T, ctx context.Context, child *components.MihomoLiveProcess, source *components.MihomoLiveSource, cm *components.Manager, provider *netidentity.Provider) {
	t.Helper()
	profile, err := child.ProfileReference(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{StateRoot: t.TempDir()}
	a := NewMihomoProbeAdapter(cm, provider)
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	r := &mihomoLiveResource{adapter: a, source: source, child: child}
	r.self = r
	r.definition.Source = source.Reference()
	r.definition.Profile = profile
	r.scope = &executionResourceScope{manager: m, mihomoLive: r}
	var late *mihomoLiveSOCKSUDPListener
	var lateCtx context.Context
	err = child.WithReadObservation(ctx, func(held context.Context, view *components.MihomoLiveObservation) error {
		role, err := r.reviewSOCKSUDPListenerRead(held, view)
		if err != nil {
			return err
		}
		late, lateCtx = role, held
		if err := role.current(held, child.PID()); err != nil {
			t.Error("actual open view/role", err)
		}
		if err := role.current(ctx, child.PID()); err == nil {
			t.Error("foreign context borrowed view")
		}
		copy := *role
		if err := copy.current(held, child.PID()); err == nil {
			t.Error("copied role borrowed view")
		}
		canceled, cancel := context.WithCancel(held)
		cancel()
		if err := role.current(canceled, child.PID()); err == nil {
			t.Error("canceled role read admitted")
		}
		// Both observations are genuinely issued by the same original child.
		// A different frame's real context still cannot borrow this view.
		return child.WithReadObservation(held, func(foreignCtx context.Context, foreignView *components.MihomoLiveObservation) error {
			if err := role.current(foreignCtx, child.PID()); err == nil {
				t.Error("foreign actual frame context admitted")
			}
			foreignRole := *role
			foreignRole.self = &foreignRole
			foreignRole.readView = foreignView
			if err := foreignRole.current(held, child.PID()); err == nil {
				t.Error("foreign actual view/context pairing admitted")
			}
			return nil
		})
	})
	if err != nil {
		t.Fatal("original view comparison", err)
	}
	if late == nil || late.current(lateCtx, child.PID()) == nil {
		t.Fatal("expired view supplied fresh role comparison")
	}
	ordinary, err := r.reviewSOCKSUDPListener(ctx)
	if err != nil || ordinary.readView != nil || ordinary.current(ctx, child.PID()) != nil {
		t.Fatal("ordinary original role changed", err)
	}
}
