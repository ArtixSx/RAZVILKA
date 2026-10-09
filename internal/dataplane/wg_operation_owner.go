package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

var ErrWGOperationOwner = errors.New("original WireGuard operation owner unavailable or changed")

type wgOperationMaterialKey struct{}
type wgOperationOwnerKey struct{}
type wgOperationCleanupKey struct{}

// WGOperationMaterial retains actual operation/control handles, not path
// evidence. Only the existing Manager's original executionResourceScope can
// issue the private command owner. Context alone grants no command permission.
type WGOperationMaterial struct {
	self    *WGOperationMaterial
	barrier sync.RWMutex
	mu      sync.Mutex
	closed  bool
	manager *Manager
	root    string
	control *operationgate.ControlEpochReview
	cleanup *operationgate.ExclusiveCleanupReview
	lan     *LANPolicyRuntimePlan
}

func (*WGOperationMaterial) String() string   { return "[private original WG operation material]" }
func (*WGOperationMaterial) GoString() string { return "[private original WG operation material]" }

// ReviewWGOperationMaterial reads genuine owners under the actual exclusive
// operation and pre-issues cleanup BEFORE effects/cancellation. LAN is only
// immutable comparison input; neither it nor this material issues a path PASS.
func ReviewWGOperationMaterial(ctx context.Context, manager *Manager, control *operationgate.ControlEpochReview, lan *LANPolicyRuntimePlan) (*WGOperationMaterial, error) {
	if ctx == nil || manager == nil || control == nil || !filepath.IsAbs(manager.StateRoot) || filepath.Clean(manager.StateRoot) != manager.StateRoot || ValidateLANPolicyRuntime(lan) != nil {
		return nil, ErrWGOperationOwner
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, ErrWGOperationOwner
	}
	if err := control.Current(ctx); err != nil {
		return nil, errors.Join(ErrWGOperationOwner, err)
	}
	cleanup, err := control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return nil, errors.Join(ErrWGOperationOwner, err)
	}
	m := &WGOperationMaterial{manager: manager, root: manager.StateRoot, control: control, cleanup: cleanup, lan: CloneLANPolicyRuntime(lan)}
	m.self = m
	return m, nil
}

func (m *WGOperationMaterial) current(ctx context.Context, cleanup bool) error {
	if m == nil || m.self != m || ctx == nil || m.manager == nil || m.manager.StateRoot != m.root || m.control == nil || m.cleanup == nil {
		return ErrWGOperationOwner
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return ErrWGOperationOwner
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return ErrWGOperationOwner
	}
	return m.cleanup.WithCurrent(ctx, func() error {
		if cleanup {
			return m.control.CurrentForCleanup(ctx)
		}
		return m.control.Current(ctx)
	})
}

// Context preserves the actual operation context. A detached, released,
// copied or foreign-operation material cannot bind a Manager phase.
func (m *WGOperationMaterial) Context(ctx context.Context) (context.Context, error) {
	if err := m.current(ctx, false); err != nil {
		return nil, errors.Join(ErrWGOperationOwner, err)
	}
	return context.WithValue(ctx, wgOperationMaterialKey{}, m), nil
}

// IsCleanupContext is comparison for the existing App review guard's private
// dispatch. Only the SAME Manager-issued original owner can match. This issues
// no context, command or cleanup capability; App must still use its original
// pre-issued cleanup review and retained physical check on every invocation.
func (m *WGOperationMaterial) IsCleanupContext(ctx context.Context) bool {
	if m == nil || m.self != m || ctx == nil || !wgOperationCleanup(ctx) || ctx.Value(wgOperationMaterialKey{}) != m {
		return false
	}
	o, _ := ctx.Value(wgOperationOwnerKey{}).(*wgOperationOwner)
	return o != nil && o.self == o && o.material == m && o.scope != nil && o.scope.manager == m.manager
}

// Close revokes and joins actual native command Wait owners. It does not close
// the caller's control/scope or release the App's original operation lease.
func (m *WGOperationMaterial) Close() error {
	if m == nil || m.self != m {
		return ErrWGOperationOwner
	}
	m.barrier.Lock()
	defer m.barrier.Unlock()
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return nil
}

type wgOperationOwner struct {
	self     *wgOperationOwner
	material *WGOperationMaterial
	scope    *executionResourceScope
	adapter  *WARPWireGuardAdapter
	shape    WARPWireGuardAdapter
	tools    WGCommandTools
	mu       sync.Mutex
	revoked  error
}

// CORE calls this once for the SAME actual Manager transaction, then keeps its
// scope through phases and joined compensation. This is not a DTO constructor.
func newWGOperationOwner(ctx context.Context, scope *executionResourceScope) (*wgOperationOwner, error) {
	if ctx == nil || scope == nil {
		return nil, ErrWGOperationOwner
	}
	m, _ := ctx.Value(wgOperationMaterialKey{}).(*WGOperationMaterial)
	if err := m.current(ctx, false); err != nil {
		return nil, errors.Join(ErrWGOperationOwner, err)
	}
	scope.mu.Lock()
	a, ok := scope.adapterOwner.(*WARPWireGuardAdapter)
	valid := ok && a != nil && (a.ID() == "wireguard" || a.ID() == "amneziawg") && scope.manager == m.manager && scope.managerRoot == m.root && reflect.DeepEqual(scope.plan.LAN, m.lan)
	if valid {
		valid = scope.checkOriginalOwner(ctx, nil, true, false) == nil
	}
	scope.mu.Unlock()
	if !valid {
		return nil, ErrWGOperationOwner
	}
	runner, ok := a.Runner.(wgExecRunner)
	if !ok || runner.adapter != a || !a.wgCommandTools.valid(a.ID()) {
		return nil, ErrWGOperationOwner
	}
	o := &wgOperationOwner{material: m, scope: scope, adapter: a, shape: *a, tools: *a.wgCommandTools}
	o.self = o
	if err := o.check(ctx, false); err != nil {
		return nil, err
	}
	return o, nil
}

func (o *wgOperationOwner) context(ctx context.Context) (context.Context, error) {
	if err := o.check(ctx, false); err != nil {
		return nil, err
	}
	return context.WithValue(o.scope.contextWith(ctx), wgOperationOwnerKey{}, o), nil
}

// Joined compensation of this SAME still-held operation only. CORE selects
// this method for rollback/deactivation phases after its original App cleanup
// and physical checks, before the adapter's existing causal receipt checks.
// It cannot acquire a fresh ACTIVE Stop operation or revive forward context.
func (o *wgOperationOwner) cleanupContext(ctx context.Context) (context.Context, error) {
	if o == nil || o.self != o || o.scope == nil || ctx == nil {
		return nil, ErrWGOperationOwner
	}
	ctx = wgNamedCleanupContext(o.scope.contextWith(ctx))
	ctx = context.WithValue(ctx, wgOperationMaterialKey{}, o.material)
	ctx = context.WithValue(ctx, wgOperationOwnerKey{}, o)
	if err := o.check(ctx, true); err != nil {
		return nil, err
	}
	return ctx, nil
}

func (o *wgOperationOwner) check(ctx context.Context, cleanup bool) error {
	if o == nil || o.self != o || o.scope == nil || o.adapter == nil || o.material == nil {
		return ErrWGOperationOwner
	}
	if err := o.material.current(ctx, cleanup); err != nil {
		return errors.Join(ErrWGOperationOwner, err)
	}
	if !o.sameAdapter() {
		return ErrWGOperationOwner
	}
	s := o.scope
	s.mu.Lock()
	err := s.checkOriginalOwner(ctx, nil, !cleanup, false)
	s.mu.Unlock()
	if err != nil {
		return errors.Join(ErrWGOperationOwner, err)
	}
	if s.networkIdentity != nil {
		if s.networkIdentity.provider != o.tools.Provider || s.networkIdentity.value != o.tools.Identity {
			return ErrWGOperationOwner
		}
		if err := s.networkIdentity.check(ctx); err != nil {
			return errors.Join(ErrWGOperationOwner, err)
		}
	}
	if err := o.tools.Runner.CheckWG(ctx, o.tools.Identity); err != nil {
		return errors.Join(ErrWGOperationOwner, err)
	}
	if !cleanup {
		o.mu.Lock()
		revoked := o.revoked
		o.mu.Unlock()
		if revoked != nil {
			return revoked
		}
	}
	// Existing App guard dispatches SAME-owner cleanup to its private
	// withCleanup (retained physics inside the pre-issued cap). All full
	// Store/profile/physical/provider reads remain outside control locks.
	if err := s.guard(ctx); err != nil {
		if cleanup {
			return errors.Join(ErrWGOperationOwner, err)
		}
		o.mu.Lock()
		o.revoked = errors.Join(ErrWGOperationOwner, err)
		revoked := o.revoked
		o.mu.Unlock()
		return revoked
	}
	return ctx.Err()
}

func (o *wgOperationOwner) sameAdapter() bool {
	if o == nil || o.adapter == nil {
		return false
	}
	a, frozen := o.adapter, &o.shape
	if a.ID() != frozen.ID() || a.StateRoot != frozen.StateRoot || a.RuntimeConfigPath != frozen.RuntimeConfigPath || a.Interface != frozen.Interface || a.Table != frozen.Table || a.PriorityBase != frozen.PriorityBase || a.WG != frozen.WG || a.IP != frozen.IP || a.WGQuick != frozen.WGQuick || a.IPTables != frozen.IPTables || a.IP6Tables != frozen.IP6Tables || a.NativeOnly != frozen.NativeOnly || !a.NativeOnly || a.Configs != frozen.Configs || !sameNetworkPolicyDependency(a.Profiles, frozen.Profiles) || !sameNetworkPolicyDependency(a.Runner, frozen.Runner) || a.wgCommandTools == nil || a.wgCommandTools != frozen.wgCommandTools {
		return false
	}
	tools := *a.wgCommandTools
	return tools.EngineID == o.tools.EngineID && tools.WG == o.tools.WG && tools.AWG == o.tools.AWG && tools.IP == o.tools.IP && tools.IPTables == o.tools.IPTables && tools.IP6Tables == o.tools.IP6Tables && tools.ReviewSHA256 == o.tools.ReviewSHA256 && tools.Identity == o.tools.Identity && tools.Provider == o.tools.Provider && sameNetworkPolicyDependency(tools.Runner, o.tools.Runner)
}

func wgOperationCleanupContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, wgOperationCleanupKey{}, true)
}

func wgOperationCleanup(ctx context.Context) bool {
	cleanup, _ := ctx.Value(wgOperationCleanupKey{}).(bool)
	return cleanup
}
