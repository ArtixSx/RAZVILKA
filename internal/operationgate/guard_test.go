package operationgate

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestDurableGuardStopsAdmissionAfterExclusiveMutation(t *testing.T) {
	var gate Gate
	var pending atomic.Bool
	blocked := errors.New("durable mutation awaits recovery")
	if err := gate.SetGuard(func(context.Context) error {
		if pending.Load() {
			return blocked
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	release, err := gate.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pending.Store(true)
	release()
	for _, enter := range []func(context.Context) (func(), error){gate.Enter, gate.Exclusive} {
		if release, err := enter(context.Background()); !errors.Is(err, blocked) || release != nil {
			t.Fatalf("pending admission: release=%v err=%v", release != nil, err)
		}
	}
	if err := gate.SetGuard(nil); !errors.Is(err, ErrBusy) {
		t.Fatal("live guard was replaced")
	}
	observe, err := gate.ObserveExclusive(context.Background(), nil)
	if err != nil {
		t.Fatal("memory-only recovery status blocked:", err)
	}
	observe()
	pending.Store(false)
	release, err = gate.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestDurableGuardDoesNotBypassPermanentRecoveryFence(t *testing.T) {
	var gate Gate
	if err := gate.SetGuard(func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	gate.FenceJournal()
	if release, err := gate.Exclusive(context.Background()); release != nil || !errors.Is(err, ErrJournalRecovery) {
		t.Fatal("journal fence bypassed:", err)
	}
}
