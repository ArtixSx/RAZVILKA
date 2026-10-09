package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

var ErrXrayOperationOwner = errors.New("original selected Xray TCP operation owner unavailable or changed")

type xrayOperationMaterialKey struct{}
type xrayOperationOwnerKey struct{}
type xrayOperationCleanupKey struct{}

// XrayOperationMaterial retains SAME actual operation/control/registered
// dispatcher and original service proof. It is preparation, never a launcher.
// Only CORE's SAME original executionResourceScope may bind its private owner;
// durable runtime publication and native socket/process proof remain required.
type XrayOperationMaterial struct {
	self         *XrayOperationMaterial
	barrier      sync.RWMutex
	closed       atomic.Bool
	closeDone    chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	manager      *Manager
	managerRoot  string
	control      *operationgate.ControlEpochReview
	cleanup      *operationgate.ExclusiveCleanupReview
	registration *XrayRegistrationReview
	adapter      *ProxyTunnelAdapter
	adapterRoot  string
	binaryField  string
	binary       string
	processes    ProcessController
	material     *xraySelectedTCPRedirectMaterial
}

func (*XrayOperationMaterial) String() string {
	return "[private original selected Xray TCP operation]"
}
func (*XrayOperationMaterial) GoString() string {
	return "[private original selected Xray TCP operation]"
}

// ReviewXrayOperationMaterial reads genuine owners and derives private config
// from the actual original Store. It pre-issues finite compensation BEFORE
// cancellation/effects. No generic callback, argv, config bytes or DTO creates
// this owner; spec is only a closed compiler match definition.
func ReviewXrayOperationMaterial(ctx context.Context, manager *Manager, control *operationgate.ControlEpochReview, original *ProxyTunnelAdapter, proof *NodeServiceProofReview, spec XraySelectedTCPRedirectSpec) (*XrayOperationMaterial, error) {
	if ctx == nil || manager == nil || control == nil || original == nil || !filepath.IsAbs(manager.StateRoot) || filepath.Clean(manager.StateRoot) != manager.StateRoot ||
		!filepath.IsAbs(original.StateRoot) || filepath.Clean(original.StateRoot) != original.StateRoot || !original.xrayPlanDispatch || !original.nodeRouterVerifier || original.scopedXray || original.xrayOperation {
		return nil, ErrXrayOperationOwner
	}
	if _, finite := ctx.Deadline(); !finite || ctx.Err() != nil {
		return nil, ErrXrayOperationOwner
	}
	if err := control.Current(ctx); err != nil {
		return nil, errors.Join(ErrXrayOperationOwner, err)
	}
	registration, err := manager.ReviewXrayRegistration(ctx, original)
	if err != nil {
		return nil, errors.Join(ErrXrayOperationOwner, err)
	}
	cleanup, err := control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		_ = registration.Close()
		return nil, errors.Join(ErrXrayOperationOwner, err)
	}
	// The original dispatcher's resolved binary is comparison data here; native executable FD,
	// version and process identity are the later runtime publisher's obligation.
	binary := original.engineBinary()
	if binary == "" || !filepath.IsAbs(binary) || filepath.Clean(binary) != binary || original.Processes == nil {
		_ = registration.Close()
		return nil, ErrXrayOperationOwner
	}
	lifetime, cancel := context.WithCancel(ctx)
	m := &XrayOperationMaterial{ctx: lifetime, cancel: cancel, closeDone: make(chan struct{}), manager: manager, managerRoot: manager.StateRoot,
		control: control, cleanup: cleanup, registration: registration, adapter: original, adapterRoot: original.StateRoot, binaryField: original.EngineBin, binary: binary, processes: original.Processes}
	m.self = m
	m.material, err = buildXraySelectedTCPRedirectMaterial(lifetime, original, proof, spec)
	if err == nil {
		err = m.current(ctx, false)
	}
	if err != nil {
		_ = m.Close()
		return nil, errors.Join(ErrXrayOperationOwner, err)
	}
	return m, nil
}

// Called under barrier after publication. The original forward context cannot
// be revived by a fresh/detached caller. Cleanup keeps only original identity
// and SAME still-held exclusive operation; expired eligibility grants no new
// process/config/selector admission.
func (m *XrayOperationMaterial) current(ctx context.Context, cleanup bool) error {
	if m == nil || m.self != m || m.closed.Load() || ctx == nil || m.manager == nil || m.adapter == nil || m.material == nil ||
		m.manager.StateRoot != m.managerRoot || m.adapter.StateRoot != m.adapterRoot || m.adapter.EngineID != "xray" || m.adapter.EngineBin != m.binaryField || m.adapter.engineBinary() != m.binary ||
		!m.adapter.xrayPlanDispatch || !m.adapter.nodeRouterVerifier || m.adapter.scopedXray || m.adapter.xrayOperation || !sameNetworkPolicyDependency(m.adapter.Processes, m.processes) {
		return ErrXrayOperationOwner
	}
	if _, finite := ctx.Deadline(); !finite || ctx.Err() != nil {
		return errors.Join(ErrXrayOperationOwner, ctx.Err())
	}
	if err := m.registration.Current(ctx); err != nil {
		return errors.Join(ErrXrayOperationOwner, err)
	}
	if cleanup {
		return errors.Join(m.control.CurrentForCleanupOperation(ctx, m.cleanup), ctx.Err())
	}
	if m.ctx.Err() != nil {
		return errors.Join(ErrXrayOperationOwner, m.ctx.Err())
	}
	deadline, _ := m.ctx.Deadline()
	forward, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(m.ctx, cancel)
	defer func() { stop(); cancel() }()
	return m.cleanup.WithCurrent(forward, func() error {
		if err := m.control.Current(forward); err != nil {
			return err
		}
		if err := m.material.current(forward, m.adapter); err != nil {
			return err
		}
		if err := m.registration.Current(forward); err != nil {
			return err
		}
		return errors.Join(m.control.Current(forward), m.ctx.Err(), forward.Err())
	})
}

// Context preserves the caller's original finite operation and values. This
// marker grants no runtime publication, command, process or effect permission.
func (m *XrayOperationMaterial) Context(ctx context.Context) (context.Context, error) {
	if m == nil || m.self != m {
		return nil, ErrXrayOperationOwner
	}
	m.barrier.RLock()
	defer m.barrier.RUnlock()
	if err := m.current(ctx, false); err != nil {
		return nil, errors.Join(ErrXrayOperationOwner, err)
	}
	return context.WithValue(ctx, xrayOperationMaterialKey{}, m), nil
}

// IsCleanupContext is comparison for CORE's App guard dispatch only. The
// independent original pre-issued cleanup review and physics remain required.
func (m *XrayOperationMaterial) IsCleanupContext(ctx context.Context) bool {
	if m == nil || m.self != m || m.closed.Load() || ctx == nil || ctx.Value(xrayOperationMaterialKey{}) != m {
		return false
	}
	cleanup, _ := ctx.Value(xrayOperationCleanupKey{}).(bool)
	o, _ := ctx.Value(xrayOperationOwnerKey{}).(*xrayOperationOwner)
	return cleanup && o != nil && o.self == o && o.material == m && o.scope != nil && o.scope.manager == m.manager
}

// Close cancels before joining in-flight reads, then erases only this leaf's
// private config. Caller-owned proof, Store, control and scope remain open.
func (m *XrayOperationMaterial) Close() error {
	if m == nil || m.self != m {
		return ErrXrayOperationOwner
	}
	if !m.closed.CompareAndSwap(false, true) {
		<-m.closeDone
		return nil
	}
	m.cancel()
	m.barrier.Lock()
	defer m.barrier.Unlock()
	if m.material != nil {
		clear(m.material.config)
		m.material.config = nil
	}
	err := m.registration.Close()
	close(m.closeDone)
	return err
}

type xrayOperationOwner struct {
	self     *xrayOperationOwner
	material *XrayOperationMaterial
	scope    *executionResourceScope
	mu       sync.Mutex
	revoked  error
}

// Binding is available only to the existing Manager's actual private scope.
// It intentionally has NO Start method until CORE publishes a concrete durable
// xraySelectedTCPRuntimeRegistration from this SAME original scope.
func newXrayOperationOwner(ctx context.Context, scope *executionResourceScope) (*xrayOperationOwner, error) {
	if ctx == nil || scope == nil {
		return nil, ErrXrayOperationOwner
	}
	m, _ := ctx.Value(xrayOperationMaterialKey{}).(*XrayOperationMaterial)
	if m == nil || m.self != m {
		return nil, ErrXrayOperationOwner
	}
	m.barrier.RLock()
	defer m.barrier.RUnlock()
	if err := m.current(ctx, false); err != nil {
		return nil, errors.Join(ErrXrayOperationOwner, err)
	}
	scope.mu.Lock()
	valid := scope.manager == m.manager && scope.managerRoot == m.managerRoot && scope.adapter == "xray" && scope.adapterOwner == m.adapter &&
		reflect.DeepEqual(scope.plan.LAN, m.material.spec.LAN) && scope.plan.NetworkProfileID == m.material.ref.WANProfile && scope.checkOriginalOwner(ctx, nil, true, false) == nil
	if valid {
		valid = xraySelectedTCPScopeRouteMatches(scope.plan, m.material)
	}
	scope.mu.Unlock()
	if !valid {
		return nil, ErrXrayOperationOwner
	}
	o := &xrayOperationOwner{material: m, scope: scope}
	o.self = o
	if err := o.checkHeld(ctx, false); err != nil {
		return nil, err
	}
	return o, nil
}

func xraySelectedTCPScopeRouteMatches(plan Plan, m *xraySelectedTCPRedirectMaterial) bool {
	count := 0
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) != "xray" {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(route.Selected)), "xray") || strings.HasPrefix(strings.ToLower(strings.TrimSpace(route.Resolved)), "xray") {
				return false
			}
			continue
		}
		count++
		service, err := FrozenProbeService(route)
		if err != nil || route.Selected != "xray:"+m.ref.NodeID || route.Resolved != route.Selected || len(route.Domains) != 0 || !reflect.DeepEqual(service, m.proof.service) ||
			!slices.Equal(sortedUnique(route.CIDRs), m.spec.Destinations) || route.NetworkPolicyGeneration != m.spec.Generation {
			return false
		}
	}
	return count == 1
}

func (o *xrayOperationOwner) checkHeld(ctx context.Context, cleanup bool) error {
	if o == nil || o.self != o || o.scope == nil || o.material == nil {
		return ErrXrayOperationOwner
	}
	if err := o.material.current(ctx, cleanup); err != nil {
		return errors.Join(ErrXrayOperationOwner, err)
	}
	o.mu.Lock()
	revoked := o.revoked
	o.mu.Unlock()
	if !cleanup && revoked != nil {
		return revoked
	}
	s := o.scope
	s.mu.Lock()
	err := s.checkOriginalOwner(ctx, nil, !cleanup, false)
	s.mu.Unlock()
	if err == nil && s.networkIdentity != nil {
		err = s.networkIdentity.check(ctx)
	}
	// Full App/provider/physical readbacks stay outside the scope metadata lock
	// and outside any durable Stop/start lock. CORE dispatches its SAME cleanup.
	if err == nil {
		err = s.guard(ctx)
	}
	if err == nil {
		s.mu.Lock()
		err = s.checkOriginalOwner(ctx, nil, !cleanup, false)
		s.mu.Unlock()
	}
	if err == nil {
		err = o.material.current(ctx, cleanup)
	}
	if err != nil && !cleanup {
		o.mu.Lock()
		o.revoked = errors.Join(ErrXrayOperationOwner, err)
		err = o.revoked
		o.mu.Unlock()
	}
	return err
}

func (o *xrayOperationOwner) context(ctx context.Context) (context.Context, error) {
	if o == nil || o.self != o || o.material == nil || o.scope == nil || ctx == nil {
		return nil, ErrXrayOperationOwner
	}
	o.material.barrier.RLock()
	defer o.material.barrier.RUnlock()
	bound := context.WithValue(o.scope.contextWith(ctx), xrayOperationMaterialKey{}, o.material)
	bound = context.WithValue(bound, xrayOperationOwnerKey{}, o)
	if err := o.checkHeld(bound, false); err != nil {
		return nil, err
	}
	return bound, nil
}

func (o *xrayOperationOwner) cleanupContext(ctx context.Context) (context.Context, error) {
	if o == nil || o.self != o || o.material == nil || o.scope == nil || ctx == nil {
		return nil, ErrXrayOperationOwner
	}
	o.material.barrier.RLock()
	defer o.material.barrier.RUnlock()
	bound := context.WithValue(o.scope.contextWith(ctx), xrayOperationMaterialKey{}, o.material)
	bound = context.WithValue(bound, xrayOperationOwnerKey{}, o)
	bound = context.WithValue(bound, xrayOperationCleanupKey{}, true)
	if err := o.checkHeld(bound, true); err != nil {
		return nil, err
	}
	return bound, nil
}
