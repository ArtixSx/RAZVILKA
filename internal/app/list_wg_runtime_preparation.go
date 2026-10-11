package app

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// WGListRuntimePreparation is the actual App source-to-compiler-to-operation
// assembly. It grants no Ready/ACTIVE state: Manager still owes original
// command-owner issuance, real Canary/Health and retained Commit/Stop ownership.
type WGListRuntimePreparation struct {
	self        *WGListRuntimePreparation
	mu          sync.Mutex
	closed      atomic.Bool
	source      *WGListRuntimeSource
	material    *dataplane.WGListSourceMaterial
	compilation *DefaultRouteCompilation
	binding     *listWGOperationBinding
	execution   *managedWGListExecution
}

func (*WGListRuntimePreparation) String() string   { return "[original WG App list preparation]" }
func (*WGListRuntimePreparation) GoString() string { return "[original WG App list preparation]" }

// Prepare reads the service from the SAME App catalog and retains its actual
// captured profile/WAN. No snapshot, path/proof DTO or guard is accepted.
func (r *WGListRuntimeSource) Prepare(ctx context.Context) (*WGListRuntimePreparation, error) {
	if err := r.Current(ctx); err != nil {
		return nil, err
	}
	var frozen catalog.Service
	found := false
	for _, service := range r.app.catalogSnapshot().Services {
		if service.ID == r.service {
			if found {
				return nil, ErrDefaultRouteCapability
			}
			frozen, found = defaultRouteCloneCatalogService(service), true
		}
	}
	if !found || frozen.ProbeURL != r.probe {
		return nil, ErrDefaultRouteCapability
	}
	material, err := dataplane.ReviewWGListSourceMaterial(ctx, r.reader, r.profile, frozen)
	if err != nil {
		return nil, err
	}
	p := &WGListRuntimePreparation{source: r, material: material}
	p.self = p
	keep := false
	defer func() {
		if !keep {
			_ = p.Close()
		}
	}()
	reference, err := material.Observation(ctx)
	if err != nil {
		return nil, err
	}
	snapshot, err := r.scope.Observe(ctx)
	if err != nil {
		return nil, err
	}
	// This epoch comes from the real retained Manager registration. The full
	// material digest binds profile, service and WAN; there is no constant PASS.
	snapshot.ProfileGeneration = reference.RegistryGeneration
	snapshot.Paths = map[string]DefaultRoutePath{r.service: {Selected: r.selected, Resolved: r.resolved, ProbeURL: r.probe,
		ProfileDigest: reference.ProfileSHA256, ProofDigest: reference.SourceSHA256, WireGuardProfileRevision: reference.ProfileRevision}}
	route := dataplane.Route{ServiceID: r.service, ServiceName: frozen.Name, Selected: r.selected, Resolved: r.resolved,
		CIDRs: slices.Clone(frozen.CIDRs), Sources: slices.Clone(r.expected.Services[r.service].Sources), ProbeURL: r.probe,
		ProbeService: &frozen, WireGuardProfileRevision: reference.ProfileRevision}
	p.compilation, err = CompileDefaultRoutePolicy(r.expected, snapshot, []dataplane.Route{route}, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if p.compilation.LAN() == nil || len(p.compilation.rules) == 0 {
		return nil, ErrDefaultRouteCapability
	}
	if err := r.Current(ctx); err != nil {
		return nil, err
	}
	if err := r.scope.BindCompilation(ctx, p.compilation); err != nil {
		return nil, err
	}
	p.binding, err = r.app.reviewListWGOperation(ctx, r.scope)
	if err != nil {
		return nil, err
	}
	if err := p.binding.material.BindSourceReview(ctx, material); err != nil {
		return nil, err
	}
	if err := p.Current(ctx); err != nil {
		return nil, err
	}
	keep = true
	return p, nil
}

func (p *WGListRuntimePreparation) Current(ctx context.Context) error {
	if p == nil || p.self != p || p.closed.Load() || p.source == nil || p.material == nil || p.compilation == nil || p.binding == nil {
		return dataplane.ErrWGOperationOwner
	}
	if err := p.source.Current(ctx); err != nil {
		return err
	}
	if err := p.material.Current(ctx); err != nil {
		return err
	}
	if err := p.source.scope.ScopeCheck(ctx, p.compilation.LAN()); err != nil {
		return err
	}
	_, err := p.binding.context(ctx)
	return err
}

// Input is detached reviewed intent. Reconstructing it supplies neither the
// actual operation material nor a private Manager-issued command owner.
func (p *WGListRuntimePreparation) Input(ctx context.Context) (dataplane.Input, error) {
	if err := p.Current(ctx); err != nil {
		return dataplane.Input{}, err
	}
	return (&DefaultRouteExecutor{app: p.source.app}).input(p.compilation, p.source.expected), nil
}

// OperationContext carries the actual pre-issued WG material and the SAME
// concrete preparation's phase guard. CORE must issue the private command
// owner from its SAME executionResourceScope and retain both through all
// Manager compensation. A context alone still grants no command.
func (p *WGListRuntimePreparation) OperationContext(ctx context.Context) (context.Context, error) {
	if err := p.Current(ctx); err != nil {
		return nil, err
	}
	ctx, err := p.binding.context(ctx)
	if err != nil {
		return nil, err
	}
	return dataplane.WithReviewGuard(ctx, p.guard), nil
}

func (p *WGListRuntimePreparation) guard(ctx context.Context) error {
	if p == nil || p.self != p || p.closed.Load() || p.binding == nil || p.compilation == nil {
		return dataplane.ErrWGOperationOwner
	}
	if p.execution != nil {
		if _, _, err := p.execution.runtime.executionFor(ctx); err != nil {
			return err
		}
	}
	if p.binding.material.IsCleanupContext(ctx) {
		if p.execution != nil {
			return p.execution.runtime.lanCleanupGuard(ctx, p.compilation.LAN(), dataplane.LANPolicyEffect{})
		}
		// Only a SAME Manager-issued cleanup owner can select this branch.
		// Forward Store/profile selection is not consulted for compensation;
		// the original cap/control and retained physical scope are checked.
		return p.binding.withCleanup(ctx, p.compilation.LAN(), func(c context.Context) error { return c.Err() })
	}
	if p.binding.material.RetainedOperationContext(ctx) {
		if p.execution == nil {
			return dataplane.ErrWGOperationOwner
		}
		return p.CurrentRetained(ctx)
	}
	return p.Current(ctx)
}

func (p *WGListRuntimePreparation) CurrentRetained(ctx context.Context) error {
	if p == nil || p.self != p || p.closed.Load() || p.execution == nil || p.binding == nil || !p.binding.material.RetainedOperationContext(ctx) {
		return dataplane.ErrWGOperationOwner
	}
	if err := p.source.currentRetained(ctx); err != nil {
		return err
	}
	if err := p.material.CurrentRetained(ctx); err != nil {
		return err
	}
	return p.source.scope.cleanupScopeCheck(ctx, p.compilation.LAN())
}

func (p *WGListRuntimePreparation) Close() error {
	if p == nil || p.self != p {
		return dataplane.ErrWGOperationOwner
	}
	p.closed.Store(true)
	p.mu.Lock()
	defer p.mu.Unlock()
	var err error
	if p.binding != nil {
		err = p.binding.close()
	}
	if p.material != nil {
		err = errors.Join(err, p.material.Close())
	}
	return err // Original source/scope/tool lease remain with their caller.
}
