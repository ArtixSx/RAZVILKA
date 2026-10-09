package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

type syntheticExecutionRegistrarKey struct{}

// CORE calls this ONLY from the existing executionResourceScope.contextWith.
// The key retains the original scope; it cannot be recovered from a Plan,
// serialized resource record, receipt, callback or successful readback.
func withSyntheticExecutionRegistrar(ctx context.Context, scope *executionResourceScope) context.Context {
	if ctx == nil || scope == nil {
		return ctx
	}
	return context.WithValue(ctx, syntheticExecutionRegistrarKey{}, scope)
}

// This is the original finite Manager bootstrap binding. Scope close revokes
// it. It is deliberately not an active listener lifetime or a publication
// grant; transferring it requires the original Manager Commit owner.
type SyntheticDNSExecutionBinding struct {
	self      *SyntheticDNSExecutionBinding
	scope     *executionResourceScope
	adapter   *ScopedDNSAdapter
	plan      Plan
	domain    *DomainPolicyRuntimePlan
	transport *SyntheticDNSTransportPlan
	dns       *dnscontrol.Manager
	root      string
	phase     *syntheticBaselineExecutionPhase
}

func (*SyntheticDNSExecutionBinding) String() string {
	return "[original finite synthetic DNS Manager binding]"
}
func (*SyntheticDNSExecutionBinding) GoString() string {
	return "[original finite synthetic DNS Manager binding]"
}

// Only the SAME registered Manager/ScopedDNSAdapter under its existing live
// operation may bind the frozen pair. A copied Ready Plan cannot create it.
func (m *Manager) BindSyntheticDNSExecution(ctx context.Context, original *ScopedDNSAdapter, expected Plan) (*SyntheticDNSExecutionBinding, error) {
	if m == nil || ctx == nil || ctx.Err() != nil || original == nil {
		return nil, ErrDomainTransportRuntime
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, ErrDomainTransportRuntime
	}
	scope, ok := ctx.Value(syntheticExecutionRegistrarKey{}).(*executionResourceScope)
	if !ok || scope == nil || scope.manager != m || scope.adapter != scopedDNSAdapterID || scope.adapterOwner != original || scope.networkIdentity == nil || scope.networkIdentity.provider == nil {
		return nil, ErrDomainTransportRuntime
	}
	frozen := cloneExecutionResourcePlan(expected)
	domain, transport, err := frozen.FrozenDomainTransport()
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(frozen, scope.plan) || original.DNS == nil || original.lifetime == nil || original.lifetime.Err() != nil || original.StateRoot != filepath.Join(scope.managerRoot, scopedDNSAdapterID) || original.InactivityIdentity != scope.networkIdentity.provider {
		return nil, ErrDomainTransportRuntime
	}
	b := &SyntheticDNSExecutionBinding{scope: scope, adapter: original, plan: frozen, domain: domain, transport: transport, dns: original.DNS, root: original.StateRoot}
	b.self = b
	if err := b.Current(ctx); err != nil {
		return nil, err
	}
	b.phase, err = newSyntheticBaselineExecutionPhase(ctx, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// External physical/profile/guard reads run outside the scope's metadata
// mutex. The existing start barrier joins them with finite scope Close. No
// detached context can revive the original operation or registry generation.
func (b *SyntheticDNSExecutionBinding) Current(ctx context.Context) error {
	if b == nil || b.self != b || b.scope == nil || b.scope.networkIdentity == nil || ctx == nil || ctx.Err() != nil {
		return ErrDomainTransportRuntime
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrDomainTransportRuntime
	}
	s := b.scope
	s.startMu.RLock()
	defer s.startMu.RUnlock()
	checkLocal := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.manager == nil || s.adapterOwner != b.adapter || b.adapter == nil || b.adapter.DNS != b.dns || b.adapter.StateRoot != b.root || b.adapter.lifetime == nil || b.adapter.lifetime.Err() != nil || b.adapter.InactivityIdentity != s.networkIdentity.provider || !reflect.DeepEqual(s.plan, b.plan) {
			return ErrDomainTransportRuntime
		}
		return s.checkOriginalOwner(ctx, nil, true, false)
	}
	if err := checkLocal(); err != nil {
		return errors.Join(ErrDomainTransportRuntime, err)
	}
	if err := s.networkIdentity.check(ctx); err != nil {
		return err
	}
	if err := verifyNetworkProfile(ctx, b.plan.NetworkProfileID, s.manager.FreshProfile); err != nil {
		return err
	}
	if err := s.guard(ctx); err != nil {
		return err
	}
	if err := s.networkIdentity.check(ctx); err != nil {
		return err
	}
	return checkLocal()
}

// Actual source-specific readback component. It retains the original mapping,
// reader and physical identity and closes with this SAME finite Manager owner.
// The result cannot publish DNS or execute a rule.
func (b *SyntheticDNSExecutionBinding) baselineInspector(ctx context.Context, original *dnscontrol.SyntheticDNSMapping, backend *BackendInventory) (*syntheticBaselineKernelInspector, error) {
	if err := b.Current(ctx); err != nil {
		return nil, err
	}
	i, err := newSyntheticBaselineKernelInspector(ctx, backend, b.scope.networkIdentity, b.transport, b.domain, original)
	if err != nil {
		return nil, err
	}
	if err := b.Current(ctx); err != nil {
		return nil, err
	}
	return i, nil
}
