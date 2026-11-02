package strategylab

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/probecheck"
	"net/netip"
	"sync"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// CandidateProbeScope is comparison material for one router-origin HTTPS
// request. It is never permission to intercept LAN or another flow on this IP.
// The caller's existing policy/network owners retain their independent checks.
type CandidateProbeScope struct {
	Target         ProbeTarget
	Address        netip.Addr
	CriteriaDigest string
}

type CandidateProbeReference struct {
	Material             SelectedCandidateReference
	ValidationGeneration string
	Scope                CandidateProbeScope
}

func ManagedProbeCriteriaDigest(service catalog.Service) (string, error) {
	return selectedReferenceDigest(struct {
		ServiceID      string
		Domains, CIDRs []string
		Probe          catalog.Probe
		Probes         []catalog.Probe
	}{service.ID, service.Domains, service.CIDRs, probecheck.ServiceProbe(service), service.Probes})
}

// CandidateProbeReview reuses the existing managed compatibility/material
// reader before there is a saved selection. It cannot be passed to the live
// selected-runtime constructor and never writes a prospective selection.
type CandidateProbeReview struct {
	self     *CandidateProbeReview
	mu       sync.Mutex
	closed   bool
	material *SelectedCandidateReview
	scope    CandidateProbeScope
}

func candidateProbeScopeValid(scope CandidateProbeScope) bool {
	u, err := validateStrategyProbeURL(scope.Target.ProbeURL)
	return err == nil && selectedReviewKeyValid(scope.Target.ServiceID, "tcp", "ipv4") && scope.Target.Protocol == "tcp" && scope.Target.IPFamily == "ipv4" && u.Scheme == "https" && (u.Port() == "" || u.Port() == "443") && scope.Address.IsValid() && scope.Address.Is4() && scope.Address.IsGlobalUnicast() && !scope.Address.IsPrivate() && !scope.Address.IsLoopback() && !scope.Address.IsLinkLocalUnicast() && compatibilityHex(scope.CriteriaDigest, 64)
}

func (m *Manager) RetainCandidateProbeReview(ctx context.Context, candidateID string, scope CandidateProbeScope, runtime *components.ManagedNFQWSRuntimeLease) (*CandidateProbeReview, error) {
	if m == nil || runtime == nil || !candidateProbeScopeValid(scope) || selectedReviewContext(ctx) != nil {
		return nil, ErrSelectedCandidateChanged
	}
	if err := runtime.Check(ctx); err != nil {
		return nil, errors.Join(ErrSelectedCandidateChanged, err)
	}
	foundation, err := newManagerAdaptiveFoundation(m)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	candidate, exists := m.state.Candidates[candidateID]
	m.mu.RUnlock()
	if !exists {
		return nil, ErrSelectedCandidateChanged
	}
	managedEpoch, err := m.currentManagedProbeEpoch(ctx, candidateID, scope.Target.ServiceID)
	if err != nil {
		return nil, err
	}
	binding, err := foundation.bind(adaptiveCandidateDetached(candidate))
	if err != nil {
		return nil, err
	}
	// This private prospective target is only a transport/material comparison.
	// sourceLocked (which requires a persisted choice) is deliberately unused.
	material := &SelectedCandidateReview{binding: binding, selection: Selection{ServiceID: scope.Target.ServiceID, Protocol: "tcp", IPFamily: "ipv4", CandidateID: candidateID}, runtime: runtime, descriptor: runtime.Descriptor(), managedEpoch: managedEpoch, canary: true}
	r := &CandidateProbeReview{material: material, scope: scope}
	r.self = r
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := material.retainSourceLocked(); err != nil {
		return nil, err
	}
	if err := material.materialCurrentLocked(ctx); err != nil {
		return nil, err
	}
	if _, err := r.referenceLocked(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *CandidateProbeReview) withCurrent(ctx context.Context, use func() error) (result error) {
	if r == nil || r.self != r || r.material == nil || use == nil || selectedReviewContext(ctx) != nil {
		return ErrSelectedCandidateChanged
	}
	r.mu.Lock()
	managedEpoch := r.material.managedEpoch
	r.mu.Unlock()
	if managedEpoch != nil {
		if err := managedEpoch.Current(ctx); err != nil {
			return err
		}
		defer func() { result = errors.Join(result, managedEpoch.Current(ctx)) }()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrSelectedCandidateChanged
	}
	m := r.material.binding.manager
	if m == nil {
		return ErrSelectedCandidateChanged
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := r.material.materialCurrentLocked(ctx); err != nil {
		return err
	}
	useErr := use()
	return errors.Join(useErr, r.material.materialCurrentLocked(ctx))
}

func (r *CandidateProbeReview) Current(ctx context.Context) error {
	return r.withCurrent(ctx, func() error { return nil })
}

func (r *CandidateProbeReview) ManagedOwnersCurrent(ctx context.Context, runtime *components.ManagedNFQWSRuntimeLease, control *operationgate.ControlEpochReview) error {
	return r.withCurrent(ctx, func() error {
		if runtime == nil || control == nil || r.material.runtime != runtime || r.material.provider == nil || r.material.provider.managedControl != control {
			return ErrSelectedCandidateChanged
		}
		return nil
	})
}

func (r *CandidateProbeReview) referenceLocked() (CandidateProbeReference, error) {
	if !compatibilityHex(r.material.binding.candidate.Validation.Generation, 32) {
		return CandidateProbeReference{}, ErrSelectedCandidateChanged
	}
	reference, err := r.material.referenceLocked()
	if err != nil {
		return CandidateProbeReference{}, err
	}
	// The first consumer supports exactly TCP443. A candidate whose explicit
	// filters include other traffic is not silently granted that wider scope.
	for _, traffic := range reference.Traffic {
		if traffic.Protocol != "tcp" || traffic.IPFamily != "ipv4" || traffic.First != 443 || traffic.Last != 443 {
			return CandidateProbeReference{}, ErrSelectedCandidateTraffic
		}
	}
	if len(reference.Traffic) == 0 {
		return CandidateProbeReference{}, ErrSelectedCandidateTraffic
	}
	return CandidateProbeReference{Material: reference, ValidationGeneration: r.material.binding.candidate.Validation.Generation, Scope: r.scope}, nil
}

func (r *CandidateProbeReview) Reference(ctx context.Context) (CandidateProbeReference, error) {
	var reference CandidateProbeReference
	err := r.withCurrent(ctx, func() error { var err error; reference, err = r.referenceLocked(); return err })
	return reference, err
}

func (r *CandidateProbeReview) ManagedReference(ctx context.Context, runtime *components.ManagedNFQWSRuntimeLease, control *operationgate.ControlEpochReview) (CandidateProbeReference, error) {
	var reference CandidateProbeReference
	err := r.withCurrent(ctx, func() error {
		if runtime == nil || control == nil || r.material.runtime != runtime || r.material.provider.managedControl != control {
			return ErrSelectedCandidateChanged
		}
		var err error
		reference, err = r.referenceLocked()
		return err
	})
	return reference, err
}

func (r *CandidateProbeReview) Close() error {
	if r == nil || r.self != r {
		return ErrSelectedCandidateChanged
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}
