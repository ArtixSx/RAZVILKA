package strategylab

import (
	"context"
	"errors"
	"testing"
	"time"
)

type timingOpaqueError struct{}

func (*timingOpaqueError) Error() string { panic("diagnostics must not format errors") }

func TestManagedCompatibilityTimingIsBoundedDetachedAndCancellationHonest(t *testing.T) {
	trace := &managedCompatibilityTiming{started: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	end := trace.begin(ctx, "phase-completion-ack", "dry-run")
	cancel()
	end(&timingOpaqueError{})
	first := trace.snapshot()
	if len(first.Entries) != 1 || !first.Entries[0].Failed || !first.Entries[0].Cancelled || !first.Entries[0].Complete {
		t.Fatal("lost actual cancellation/refusal", first)
	}
	first.Entries[0].Stage = "caller changed the detached copy"
	if trace.snapshot().Entries[0].Stage != "phase-completion-ack" {
		t.Fatal("getter aliases original diagnostic buffer")
	}
	for range managedCompatibilityTimingLimit * 2 {
		trace.begin(context.Background(), "publication-guard", "publication")(nil)
	}
	bounded := trace.snapshot()
	if len(bounded.Entries) != managedCompatibilityTimingLimit || bounded.Dropped != managedCompatibilityTimingLimit+1 {
		t.Fatal("unbounded or silently lost trace", len(bounded.Entries), bounded.Dropped)
	}
}

func TestManagedCompatibilityTimingGetterDoesNotObserveInvalidSourceOrOwner(t *testing.T) {
	trace := &managedCompatibilityTiming{started: time.Now()}
	trace.begin(context.Background(), "completion-retire", "cleanup")(nil)
	p := &SupervisedCompatibilityProvider{managedTiming: trace}
	// No file, control, process or valid factory is supplied. The getter can
	// copy diagnostics only; it cannot run any of those owners' real observers.
	m := &Manager{Path: "this deliberately is not an absolute source", Validator: CompatibleValidator{Provider: p}}
	if got := m.ManagedCompatibilityTimings(); len(got.Entries) != 1 || !got.Entries[0].Complete {
		t.Fatal("pure diagnostic copy unavailable", got)
	}
	if m.Path != "this deliberately is not an absolute source" {
		t.Fatal("getter repaired source")
	}
	var absent *Manager
	if got := absent.ManagedCompatibilityTimings(); got.Schema != 1 || len(got.Entries) != 0 {
		t.Fatal(got)
	}
}

func TestManagedCompatibilityTimingCannotChangeActualGuardRefusal(t *testing.T) {
	i := &managedCompatibilityInvocation{timing: &managedCompatibilityTiming{started: time.Now()}}
	ctx := context.WithValue(context.Background(), managedCompatibilityContextKey{}, i)
	m := &Manager{}
	if err := m.prepareCompatibilityPublicationLocked(ctx, Validation{}); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatal("diagnostic altered real refusal", err)
	}
	got := i.timing.snapshot()
	if len(got.Entries) != 1 || got.Entries[0].Stage != "publication-guard" || !got.Entries[0].Failed {
		t.Fatal("actual guard timing not captured", got)
	}
	var absent *managedCompatibilityInvocation
	if err := absent.cleanupCurrent(context.Background()); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatal("nil original owner semantics changed", err)
	}
}
