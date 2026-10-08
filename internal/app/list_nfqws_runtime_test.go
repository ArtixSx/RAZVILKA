package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

func TestManagedNFQListMissingOrCopiedOwnerNeverAdmits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	original := &ManagedNFQWSListRuntime{}
	original.self = original
	copy := &ManagedNFQWSListRuntime{self: original}
	for _, r := range []*ManagedNFQWSListRuntime{nil, {}, original, copy} {
		if _, err := r.Start(ctx, "service", "tcp", "ipv4"); !errors.Is(err, dataplane.ErrNFQWSScopedOwner) {
			t.Fatal("invalid runtime started", err)
		}
		if err := r.Current(ctx); err == nil {
			t.Fatal("invalid runtime became current")
		}
		if err := r.Stop(ctx); err == nil {
			t.Fatal("invalid runtime retired")
		}
		if err := r.WithStart(ctx, "ip", nil, "", func() error { t.Fatal("invalid runtime command started"); return nil }); err == nil {
			t.Fatal("invalid command admitted")
		}
	}
}

// Actual control/Gate lifecycle; pending execution is an explicit refusal
// model, never a claimed process or cleanup capability.
func TestManagedNFQListPendingKeepsOriginalControlOpen(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	control, err := a.managedNFQControl(c)
	if err != nil {
		t.Fatal(err)
	}
	a.retainManagedNFQControl(control)
	r := &ManagedNFQWSListRuntime{app: a, pending: &managedNFQWSListExecution{}}
	a.managedNFQList = r
	if err := a.CloseManagedNFQControl(); !errors.Is(err, strategylab.ErrCompatibilityQuiescenceUnknown) {
		t.Fatal("unknown list owner released control", err)
	}
	if err := control.Current(c); err != nil {
		t.Fatal("original control closed before retirement", err)
	}
	r.pending = nil
	if err := a.CloseManagedNFQControl(); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultRouteNFQListInitialConfigDoesNotBypassOriginalScopeApproval(t *testing.T) {
	cfg, snapshot, routes, now := defaultRouteNFQWSComparisonFixture("tcp", "ipv4")
	cfg.Revision = 0
	compiled, err := CompileDefaultRoutePolicy(cfg, snapshot, routes, now)
	if err == nil || compiled != nil || cfg.Revision != 0 {
		t.Fatal("initial unapproved config acquired scope or was edited", err)
	}
}
