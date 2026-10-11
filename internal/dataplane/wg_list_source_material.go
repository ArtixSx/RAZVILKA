package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// WGListSourceMaterial retains the actual profile, registered tool source and
// numeric WAN that can carry one frozen service. It is preparation for the
// original Manager Canary/Activate, never a handshake or effect receipt.
type WGListSourceMaterial struct {
	self      *WGListSourceMaterial
	barrier   sync.RWMutex
	mu        sync.Mutex
	closed    atomic.Bool
	invalid   bool
	reader    *WGSourceReadReview
	profile   *WGSourceProfileCapture
	service   catalog.Service
	wan       WGEndpointState
	sources   []netip.Addr
	reference WGListSourceMaterialReference
}

// RegistryGeneration is the actual Manager registration epoch of the retained
// source, not a caller counter or a claim of network health. ProfileSHA256 and
// SourceSHA256 additionally freeze its exact profile and service/WAN predicate.
type WGListSourceMaterialReference struct {
	EngineID, ServiceID, ProfileID, ProfileRevision string
	RegistryGeneration                              uint64
	ProfileSHA256, SourceSHA256                     string
}

func (*WGListSourceMaterial) String() string   { return "[original WG list source material]" }
func (*WGListSourceMaterial) GoString() string { return "[original WG list source material]" }

func ReviewWGListSourceMaterial(ctx context.Context, reader *WGSourceReadReview, profile *WGSourceProfileCapture, service catalog.Service) (*WGListSourceMaterial, error) {
	if reader == nil || reader.self != reader || profile == nil || profile.self != profile || profile.reader != reader || reader.registry == 0 || len(service.Domains) != 0 || len(service.CIDRs) == 0 {
		return nil, ErrWGOperationOwner
	}
	frozen, err := FrozenProbeService(Route{LogicalServiceID: service.ID, ProbeService: &service, ProbeURL: service.ProbeURL})
	if err != nil {
		return nil, errors.Join(ErrWGOperationOwner, err)
	}
	for _, raw := range frozen.CIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Bits() == 0 || prefix.Masked().String() != raw || prefix.Addr().Is4In6() {
			return nil, ErrWGNetworkPolicy
		}
	}
	if err := profile.Current(ctx); err != nil {
		return nil, err
	}
	wan, err := reader.ObserveNumericEndpoint(ctx, profile)
	if err != nil {
		return nil, err
	}
	sources, err := wgNetworkProfileSources(ctx, profile.content, frozen.CIDRs)
	if err != nil {
		return nil, err
	}
	if reader.adapter.ID() == "amneziawg" {
		if _, _, err := reader.adapter.advancedAWGTool(ctx, profile.content); err != nil {
			return nil, err
		}
	}
	meta, err := profile.Observation(ctx)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(struct {
		Profile  WGSourceProfileObservation
		Service  catalog.Service
		WAN      WGEndpointState
		Registry uint64
	}{meta, frozen, wan, reader.registry})
	if err != nil {
		return nil, err
	}
	r := &WGListSourceMaterial{reader: reader, profile: profile, service: frozen, wan: wan, sources: slices.Clone(sources),
		reference: WGListSourceMaterialReference{EngineID: meta.EngineID, ServiceID: frozen.ID, ProfileID: meta.ProfileID, ProfileRevision: meta.Revision,
			RegistryGeneration: reader.registry, ProfileSHA256: meta.ContentSHA256, SourceSHA256: routeidentity.Hash(encoded)}}
	r.self = r
	if err := r.Current(ctx); err != nil {
		_ = r.Close()
		return nil, err
	}
	return r, nil
}

func (r *WGListSourceMaterial) Current(ctx context.Context) error {
	if r == nil || r.self != r || ctx == nil || r.closed.Load() {
		return ErrWGOperationOwner
	}
	r.barrier.RLock()
	defer r.barrier.RUnlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() || r.invalid {
		return ErrWGOperationOwner
	}
	err := r.current(ctx)
	if err != nil {
		r.invalid = true
	}
	return err
}

func (r *WGListSourceMaterial) current(ctx context.Context) error {
	if err := r.profile.Current(ctx); err != nil {
		return err
	}
	if r.reader.registry != r.reference.RegistryGeneration {
		return ErrWGOperationOwner
	}
	wan, err := r.reader.ObserveNumericEndpoint(ctx, r.profile)
	// Numeric endpoints have no DNS lease. A new inspection timestamp is
	// not a changed WAN tuple and must not renew the frozen source predicate.
	wan.ResolvedAt = r.wan.ResolvedAt
	if err != nil || !wan.ExpiresAt.IsZero() || !reflect.DeepEqual(wan, r.wan) {
		return errors.Join(ErrWGOperationOwner, err)
	}
	sources, err := wgNetworkProfileSources(ctx, r.profile.content, r.service.CIDRs)
	if err != nil || !slices.Equal(sources, r.sources) {
		return errors.Join(ErrWGNetworkPolicy, err)
	}
	if r.reader.adapter.ID() == "amneziawg" {
		if _, _, err := r.reader.adapter.advancedAWGTool(ctx, r.profile.content); err != nil {
			return err
		}
	}
	return r.profile.Current(ctx)
}

func (r *WGListSourceMaterial) Observation(ctx context.Context) (WGListSourceMaterialReference, error) {
	if err := r.Current(ctx); err != nil {
		return WGListSourceMaterialReference{}, err
	}
	return r.reference, nil
}

// Close joins source inspections, but leaves the caller's original reader,
// scope, startup lease and control available for joined compensation.
func (r *WGListSourceMaterial) Close() error {
	if r == nil || r.self != r {
		return ErrWGOperationOwner
	}
	r.closed.Store(true)
	r.barrier.Lock()
	defer r.barrier.Unlock()
	return nil
}
