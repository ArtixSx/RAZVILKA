package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type sharedWGInactivityModel struct {
	*wgInactivityProcessModel
	inside *bool
}

func (m *sharedWGInactivityModel) CheckWG(ctx context.Context, identity netidentity.Identity) error {
	if *m.inside {
		return errors.New("full startup check reentered Provider boundary")
	}
	return m.wgInactivityProcessModel.CheckWG(ctx, identity)
}

func (m *sharedWGInactivityModel) RunWG(ctx context.Context, admission WGCommandAdmission, name string, args ...string) ([]byte, error) {
	if *m.inside {
		return nil, errors.New("full inactivity read reentered Provider boundary")
	}
	return m.wgInactivityProcessModel.RunWG(ctx, admission, name, args...)
}

// Actual paired registration, operation/control and source/file sessions;
// optional tools, NI and kernel command results are explicit portable models.
func sharedWGInactivityFixture(t *testing.T) (*wgSourceReadFixture, Plan, *NetworkPolicyChecks, [2]*sharedWGInactivityModel, *bool) {
	t.Helper()
	f := newWGSourceReadFixture(t)
	tools := *f.a.wgCommandTools
	program, err := os.ReadFile(tools.IP)
	if err != nil {
		t.Fatal(err)
	}
	tools.IP = filepath.Join(t.TempDir(), "ip-model.exe")
	if err := os.WriteFile(tools.IP, program, 0700); err != nil {
		t.Fatal(err)
	}
	tools.WG, tools.AWG = "", ""
	m := New(t.TempDir())
	for _, a := range []*WARPWireGuardAdapter{NewWireGuardAdapter(f.a.Configs, m.StateRoot), NewAmneziaWGAdapter(f.a.Configs, m.StateRoot)} {
		if err := m.Register(a); err != nil {
			t.Fatal(err)
		}
	}
	_, plan, originalGate, _, _ := networkPolicyGateManagerFixture(t)
	inside := false
	identity := &networkPolicyIdentity{provider: tools.Provider, value: tools.Identity, mode: LANPolicyManagedListMode}
	identity.withCurrent = func(ctx context.Context, use func(context.Context, netidentity.Identity) error) error {
		if inside {
			return errors.New("reentrant Provider model")
		}
		inside = true
		defer func() { inside = false }()
		return use(ctx, identity.value)
	}
	originalGate.Binding.Runtime.IP, originalGate.Binding.Runtime.IPTables, originalGate.Binding.Runtime.IP6Tables = tools.IP, tools.IPTables, tools.IP6Tables
	gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Mode: LANPolicyManagedListMode, Binding: originalGate.Binding,
		InventoryCheck: func(context.Context, netidentity.Identity, *LANPolicyRuntimePlan) error { return nil }}, identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Register(gate); err != nil {
		t.Fatal(err)
	}
	checks, err := m.bindNetworkPolicyChecks(gate, func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error) {
		return networkPolicyInventoryTestImage(identity.value, nil), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = checks.Close() })
	sources := make(map[string]*WGInactivityRead, 2)
	var models [2]*sharedWGInactivityModel
	for i, id := range []string{"wireguard", "amneziawg"} {
		models[i] = &sharedWGInactivityModel{wgInactivityProcessModel: &wgInactivityProcessModel{base: f.model}, inside: &inside}
		tools.EngineID, tools.Runner = id, models[i]
		source, err := ReviewWGInactivityRead(f.ctx, context.Background(), m, f.control, tools)
		if err != nil {
			t.Fatal(err)
		}
		sources[id] = source
		t.Cleanup(func() { _ = source.Close() })
	}
	if err := checks.BindManagedWGInactivitySources(f.ctx, sources); err != nil {
		t.Fatal(err)
	}
	delete(sources, "wireguard") // Caller map mutation cannot alter frozen owners.
	return f, plan, checks, models, &inside
}

func TestManagedWGRetireObservesBothOriginalSourcesOutsideProvider(t *testing.T) {
	f, plan, checks, models, inside := sharedWGInactivityFixture(t)
	err := checks.RetireCheck(f.ctx, plan.LAN)
	for i, model := range models {
		if model.calls.Load() < 10 {
			t.Fatal("whole original observer skipped", i, model.calls.Load(), err)
		}
	}
	if *inside {
		t.Fatal("Provider bracket leaked")
	}
	// Windows' actual process observer must refuse; the explicit IP model
	// and CLI absence cannot convert its unknown result to inactivity.
	if os.PathSeparator == '\\' && err == nil {
		t.Fatal("unsupported process observer became absence")
	}
}

func TestManagedWGPairedOriginalSessionBookendsAndFreshCleanup(t *testing.T) {
	f, _, checks, _, _ := sharedWGInactivityFixture(t)
	cleanup, err := f.control.ReviewExclusiveCleanup(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.cancel()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(f.ctx), 3*time.Second)
	defer cancel()
	ctx = WithWGInactivityCleanup(ctx, cleanup)
	var escaped [2]context.Context
	// Exercise the actual session and Provider closing seam without replacing
	// a full inactivity observer or granting any native retirement.
	if err := checks.withWGInactivitySessions(ctx, func(original [2]context.Context, bookends func() error) error {
		escaped = original
		return checks.boundary(ctx, func(held context.Context) error {
			return errors.Join(checks.retiredWGInventory(held, nil), bookends())
		})
	}); err != nil {
		t.Fatal("nested sessions lost the first source's original context", err)
	}
	for i, id := range []string{"wireguard", "amneziawg"} {
		if checks.wgInactivity[id].CurrentFiles(escaped[i]) == nil {
			t.Fatal("closed source callback revived", id)
		}
	}
	if err := checks.withWGInactivitySessions(ctx, func(_ [2]context.Context, bookends func() error) error {
		return checks.boundary(ctx, func(context.Context) error {
			if err := os.MkdirAll(checks.wgInactivity["wireguard"].adapter.StateRoot, 0700); err != nil {
				return err
			}
			return bookends()
		})
	}); err == nil {
		t.Fatal("closing original subtree change was accepted")
	}
	f.release()
	if err := checks.withWGInactivitySessions(ctx, func([2]context.Context, func() error) error { return nil }); err == nil {
		t.Fatal("released App cleanup review revived read sessions")
	}
}
