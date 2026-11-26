package dataplane

import (
	"context"
	"errors"
	"sync"
)

var ErrXrayRegistration = errors.New("original registered Xray owner unavailable or changed")

// XrayRegistrationReview observes one actual registered pointer/generation.
// It grants no process, runtime readiness, scope, probe or effect authority.
type XrayRegistrationReview struct {
	self            *XrayRegistrationReview
	mu              sync.Mutex
	closed, invalid bool
	manager         *Manager
	managerRoot     string
	adapter         *ProxyTunnelAdapter
	adapterRoot     string
	generation      uint64
}

func (m *Manager) ReviewXrayRegistration(ctx context.Context, original *ProxyTunnelAdapter) (*XrayRegistrationReview, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrXrayRegistration
	}
	if _, finite := ctx.Deadline(); !finite || m == nil || m.StateRoot == "" || original == nil || original.EngineID != "xray" || original.StateRoot == "" {
		return nil, ErrXrayRegistration
	}
	m.registryMu.RLock()
	registered, generation := m.Adapters["xray"], m.registryGeneration
	m.registryMu.RUnlock()
	if registered != original {
		return nil, ErrXrayRegistration
	}
	r := &XrayRegistrationReview{manager: m, managerRoot: m.StateRoot, adapter: original, adapterRoot: original.StateRoot, generation: generation}
	r.self = r
	if err := r.Current(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// Each call requires its fresh finite context; construction ctx is not an
// operation lease. The original App source separately owns scope/admission.
func (r *XrayRegistrationReview) Current(ctx context.Context) error {
	if r == nil || r.self != r || ctx == nil || ctx.Err() != nil {
		return ErrXrayRegistration
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrXrayRegistration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.invalid || r.manager == nil || r.adapter == nil {
		return ErrXrayRegistration
	}
	r.manager.registryMu.RLock()
	valid := r.manager.StateRoot == r.managerRoot && r.adapter.StateRoot == r.adapterRoot && r.adapter.EngineID == "xray" &&
		r.manager.registryGeneration == r.generation && r.manager.Adapters["xray"] == r.adapter
	r.manager.registryMu.RUnlock()
	if !valid {
		r.invalid = true
		return ErrXrayRegistration
	}
	return ctx.Err()
}

func (r *XrayRegistrationReview) Close() error {
	if r == nil || r.self != r {
		return ErrXrayRegistration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}
