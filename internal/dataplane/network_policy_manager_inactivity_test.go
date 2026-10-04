package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type networkPolicyInactiveObserver struct {
	*fakeAdapter
	observe func(context.Context) error
	calls   int
}

func (a *networkPolicyInactiveObserver) VerifyRuntimeInactive(ctx context.Context) error {
	a.calls++
	if a.observe != nil {
		return a.observe(ctx)
	}
	return nil
}

func TestNetworkPolicyManagerInactiveRequiresEveryOwner(t *testing.T) {
	m := New(t.TempDir())
	if err := m.VerifyRuntimeInactive(context.Background()); err == nil {
		t.Fatal("empty registry treated as complete inventory")
	}
	good := &networkPolicyInactiveObserver{fakeAdapter: &fakeAdapter{id: "good"}}
	bad := &networkPolicyInactiveObserver{fakeAdapter: &fakeAdapter{id: "bad"}, observe: func(context.Context) error { return errors.New("unknown incarnation") }}
	for _, a := range []Adapter{good, bad, &fakeAdapter{id: "unused"}} {
		if err := m.Register(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.VerifyRuntimeInactive(context.Background()); !errors.Is(err, ErrRuntimeInactivity) || good.calls != 1 || bad.calls != 1 {
		t.Fatal("missing/failed owner silently skipped or stopped remaining observations", err)
	}
	if len(good.fakeAdapter.calls) != 0 || len(bad.fakeAdapter.calls) != 0 {
		t.Fatal("inactivity observation performed lifecycle effects")
	}
}

func TestNetworkPolicyManagerInactiveSuccessIsFreshAndReadOnly(t *testing.T) {
	root := t.TempDir()
	m := New(root)
	a := &networkPolicyInactiveObserver{fakeAdapter: &fakeAdapter{id: "owned"}}
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := m.VerifyRuntimeInactive(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 || a.calls != 2 {
		t.Fatal("observation cached or wrote journal", entries, err)
	}
}

func TestNetworkPolicyManagerInactiveRejectsRegistryAndRecoveryChanges(t *testing.T) {
	for _, change := range []string{"registry", "recovery"} {
		t.Run(change, func(t *testing.T) {
			m := New(t.TempDir())
			a := &networkPolicyInactiveObserver{fakeAdapter: &fakeAdapter{id: "owned"}, observe: func(context.Context) error {
				if change == "registry" {
					return m.Register(&networkPolicyInactiveObserver{fakeAdapter: &fakeAdapter{id: "new"}})
				}
				return os.WriteFile(filepath.Join(m.StateRoot, "latest-execution.json"), []byte(`{"state":"applying"}`), 0600)
			}}
			if err := m.Register(a); err != nil {
				t.Fatal(err)
			}
			if err := m.VerifyRuntimeInactive(context.Background()); err == nil {
				t.Fatal("changing authority accepted")
			}
			if change == "recovery" {
				if err := m.VerifyRuntimeInactive(context.Background()); !errors.Is(err, ErrExecutionJournal) || a.calls != 1 {
					t.Fatal("unfinished fence not checked before observers", err)
				}
			}
		})
	}
}

func TestNetworkPolicyManagerInactiveSharesOperationGate(t *testing.T) {
	m := New(t.TempDir())
	a := &networkPolicyInactiveObserver{fakeAdapter: &fakeAdapter{id: "owned"}}
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	if err := m.beginOperation(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.endOperation()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := m.VerifyRuntimeInactive(ctx); !errors.Is(err, context.DeadlineExceeded) || a.calls != 0 {
		t.Fatal("observer raced lifecycle operation", err)
	}
}
