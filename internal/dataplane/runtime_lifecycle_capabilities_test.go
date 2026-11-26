package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"net/netip"
	"testing"
)

func TestLifecycleRegistryDoesNotRunAdapterOrChecker(t *testing.T) {
	manager := New(t.TempDir())
	adapter := NewWARPWireGuardAdapter(nil, manager.StateRoot)
	adapter.Runner = handshakeBudgetRunner(func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("read-only lifecycle started a command")
		return nil, nil
	})
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	got := manager.AdapterLifecycleRegistration(adapter.ID())
	if !got.Registered || !got.StagedValidation || !got.LiveApply || !got.LiveHealth || !got.IsolatedProbe || !got.Recovery || !got.Rollback {
		t.Fatal("registered adapter lifecycle lost")
	}
	if manager.AdapterLifecycleRegistration("missing").Registered {
		t.Fatal("missing adapter invented")
	}
	checker := NewExactNodeChecker(t.TempDir())
	checker.Binary = "not-installed"
	gotCheck := checker.NodeCheckLifecycleRegistration()
	if !gotCheck.NativeValidation || !gotCheck.IsolatedProbe {
		t.Fatal("configured exact pipeline lost")
	}
	checker.prepare = func(context.Context, exactNodeSession, NodeCheckRequest, exactNodeEndpoint) (exactNodeSession, error) {
		t.Fatal("capability executed prepare")
		return exactNodeSession{}, nil
	}
	if checker.NodeCheckLifecycleRegistration().NativeValidation {
		t.Fatal("opaque replaced prepare claimed native validator")
	}
	checker.serviceIPProbe = func(context.Context, string, string, string, catalog.Service, netip.Addr) (evidence.ProbeEvidence, error) {
		t.Fatal("capability probed service")
		return evidence.ProbeEvidence{}, nil
	}
}
