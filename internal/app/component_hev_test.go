package app

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func hevApplicationGuardFixture(t *testing.T) *App {
	t.Helper()
	base := t.TempDir()
	store, err := config.Load(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	root := filepath.Join(base, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, root); err != nil {
		t.Fatal(err)
	}
	return &App{Store: store, SelfUpdateFiles: &SelfUpdateFiles{ControlRoot: root}}
}

func TestHEVForwardGuardOriginalEpochAndClosingSettings(t *testing.T) {
	a := hevApplicationGuardFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	owned, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	control, err := a.Operations.ReviewControlEpoch(owned, a.SelfUpdateFiles.ControlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	guard := a.hevForwardGuard(a.Store.Get(), control)
	calls := 0
	effect := func() error { calls++; return nil }
	if err := guard(owned, effect); err != nil || calls != 1 {
		t.Fatal(calls, err)
	}
	if err := guard(ctx, effect); err == nil || calls != 1 {
		t.Fatal("detached context admitted", calls, err)
	}
	foreign, free, err := (&operationgate.Gate{}).ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer free()
	if err := guard(foreign, effect); err == nil || calls != 1 {
		t.Fatal("foreign gate admitted", calls, err)
	}
	cause := errors.New("publication failed")
	err = guard(owned, func() error {
		if e := a.Store.UpdateService("youtube", config.ServiceState{Enabled: false, Route: "direct"}); e != nil {
			t.Fatal(e)
		}
		return cause
	})
	if !errors.Is(err, cause) || !errors.Is(err, config.ErrRevisionChanged) {
		t.Fatal("lost publication or closing failure", err)
	}
	if err := guard(owned, effect); err == nil || calls != 1 {
		t.Fatal("stale settings admitted", calls, err)
	}
}

func TestHEVForwardGuardCancellationAfterEffect(t *testing.T) {
	a := hevApplicationGuardFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	owned, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	control, err := a.Operations.ReviewControlEpoch(owned, a.SelfUpdateFiles.ControlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	err = a.hevForwardGuard(a.Store.Get(), control)(owned, func() error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal("closing cancellation lost", err)
	}
}

func TestHEVInstallRequiresConfiguredFleetBeforeComponentEffects(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := a.installHEV(ctx); err == nil {
		t.Fatal("custom state root bypassed retained fleet")
	}
}
