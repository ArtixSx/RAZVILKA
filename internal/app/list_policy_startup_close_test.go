package app

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestManagedListStartupFailedOriginalAttemptClosesAndKeepsStage(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	a.Dataplane = &dataplane.Manager{StateRoot: filepath.Join(t.TempDir(), "state")}
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	panel, closePanel := context.WithCancel(context.Background())
	defer closePanel()
	first, err := a.ConfigureReviewedStockNFQWSList(parent, panel)
	if first != nil || err == nil || ManagedListStartupFailureStage(err) != "operation" {
		t.Fatal("failed actual operation lost startup stage", err)
	}
	p := a.managedListPolicy
	if p == nil || p.self != p || p.app != a || !p.closed.Load() || p.startupFailure == nil || p.startupReady {
		t.Fatal("original failed attempt was not retained and closed")
	}
	second, secondErr := a.ConfigureReviewedStockXraySelectedTCPList(context.Background(), panel)
	if second != nil || secondErr == nil || ManagedListStartupFailureStage(secondErr) != "operation" || a.managedListPolicy != p {
		t.Fatal("second constructor replaced or hid original failed attempt", secondErr)
	}
	ctx, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	if err := a.CloseManagedListStartup(ctx); err != nil {
		t.Fatal("actual preeffect attempt did not join", err)
	}
	if err := a.CloseManagedListStartup(ctx); err != nil {
		t.Fatal("closed original attempt was not idempotent", err)
	}
	foreign := &App{Dataplane: a.Dataplane, managedListPolicy: p}
	if err := foreign.CloseManagedListStartup(ctx); !errors.Is(err, dataplane.ErrRuntimeInactivity) {
		t.Fatal("foreign App adopted closed startup", err)
	}
	if err := (&App{Dataplane: a.Dataplane}).CloseManagedListStartup(ctx); !errors.Is(err, dataplane.ErrRuntimeInactivity) {
		t.Fatal("nil runtime pointers supplied proof", err)
	}
}

func TestManagedListStartupUnknownRuntimeCannotUsePreeffectClose(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	a.Dataplane = &dataplane.Manager{StateRoot: filepath.Join(t.TempDir(), "state")}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	failed, stop := context.WithCancel(ctx)
	stop()
	if _, err := a.ConfigureReviewedStockNFQWSList(failed, context.Background()); err == nil {
		t.Fatal("cancelled constructor admitted")
	}
	p := a.managedListPolicy
	// This is only a refusal model. No process or cleanup authority is minted.
	r := &ManagedNFQWSListRuntime{app: a, manager: a.Dataplane, policy: p, pending: &managedNFQWSListExecution{}}
	r.self = r
	a.managedNFQList, p.nfq = r, r
	if err := a.CloseManagedListStartup(ctx); !errors.Is(err, dataplane.ErrRuntimeInactivity) {
		t.Fatal("unknown runtime was discarded after nil constructor result", err)
	}
	if r.pending == nil || p.nfq != r {
		t.Fatal("refusal destroyed original pending slot")
	}
	p.nfqClosed = true
	r.closed = true
	if err := a.CloseManagedListStartup(ctx); !errors.Is(err, dataplane.ErrRuntimeInactivity) {
		t.Fatal("closed flag converted pending native owner to retired", err)
	}
	if err := a.CloseManagedListStartup(context.Background()); !errors.Is(err, dataplane.ErrRuntimeInactivity) {
		t.Fatal("unbounded close admitted", err)
	}
}

func TestManagedListStartupFailedJoinCannotBecomeSuccessOnRetry(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	a.Dataplane = &dataplane.Manager{StateRoot: filepath.Join(t.TempDir(), "state")}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	failed, stop := context.WithCancel(ctx)
	stop()
	if _, err := a.ConfigureReviewedStockNFQWSList(failed, context.Background()); err == nil {
		t.Fatal("cancelled constructor admitted")
	}
	p := a.managedListPolicy
	// Explicit failed-close outcome model, no native or descriptor grant. A
	// Close implementation may return nil on repeats after revoking itself;
	// that cannot erase the original unknown join recorded by this owner.
	unknown := errors.New("original startup descriptor close unconfirmed")
	p.closed.Store(false)
	p.closeErr = unknown
	for i := 0; i < 3; i++ {
		if err := a.CloseManagedListStartup(ctx); !errors.Is(err, unknown) {
			t.Fatal("retry erased original failed join", i, err)
		}
		if p.closed.Load() {
			t.Fatal("retry published joined startup after failed original close")
		}
	}
}
