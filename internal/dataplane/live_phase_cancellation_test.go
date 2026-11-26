package dataplane

import (
	"context"
	"errors"
	"slices"
	"testing"
)

type livePhaseCancellationAdapter struct {
	*fakeAdapter
	cancel   context.CancelFunc
	cancelAt string
	settled  bool
}

func (a *livePhaseCancellationAdapter) phase(ctx context.Context, phase string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.call(phase); err != nil {
		return err
	}
	if phase == a.cancelAt {
		a.cancel()
		if phase == "activate" {
			// Cancellation after admission must still let the entered phase
			// settle its kernel work; the next phase must not start.
			a.settled = ctx.Err() == nil
			return ctx.Err()
		}
	}
	return nil
}
func (a *livePhaseCancellationAdapter) Canary(ctx context.Context, _ RoutePlan, _ string) error {
	return a.phase(ctx, "canary")
}
func (a *livePhaseCancellationAdapter) Activate(ctx context.Context, _ Plan, _ string) error {
	return a.phase(ctx, "activate")
}
func (a *livePhaseCancellationAdapter) Health(ctx context.Context, _ Plan, _ string) error {
	return a.phase(ctx, "health")
}
func (a *livePhaseCancellationAdapter) Commit(ctx context.Context, _ Plan, _ string) error {
	return a.phase(ctx, "commit-adapter")
}
func (a *livePhaseCancellationAdapter) Deactivate(ctx context.Context) error {
	return a.phase(ctx, "deactivate")
}

func TestManagerCanceledContextCannotEnterNextLivePhase(t *testing.T) {
	for _, target := range []string{"activate", "deactivate", "commit-adapter"} {
		t.Run(target, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m := New(t.TempDir())
			a := &livePhaseCancellationAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}, cancel: cancel, cancelAt: "canary"}
			if target == "commit-adapter" {
				a.cancelAt = "health"
			}
			if err := m.Register(a); err != nil {
				t.Fatal(err)
			}
			plan := journalTestPlan() // No network-proof callback to mask admission.
			forbidden := a.fakeAdapter
			if target == "deactivate" {
				retiring := &livePhaseCancellationAdapter{fakeAdapter: &fakeAdapter{id: "nfqws2"}}
				if err := m.Register(retiring); err != nil {
					t.Fatal(err)
				}
				plan.RetiringAdapters = []string{retiring.ID()}
				forbidden = retiring.fakeAdapter
			}
			_, err := m.Apply(ctx, plan, nil)
			if !errors.Is(err, context.Canceled) || slices.Contains(forbidden.calls, target) {
				t.Fatal("canceled operation entered live phase", forbidden.calls, err)
			}
		})
	}
}

func TestManagerEnteredLivePhaseSettlesBeforeCanceledRollback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := New(t.TempDir())
	a := &livePhaseCancellationAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}, cancel: cancel, cancelAt: "activate"}
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	execution, err := m.Apply(ctx, journalTestPlan(), nil)
	if !errors.Is(err, context.Canceled) || !a.settled || !a.rollback || slices.Contains(a.calls, "health") || execution.State != "rolled-back" {
		t.Fatal("entered phase did not settle and roll back", a.calls, a.settled, execution.State, err)
	}
}
