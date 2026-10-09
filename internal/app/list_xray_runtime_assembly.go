package app

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// One immutable preparation under the source's SAME original App operation.
// The compiler uses actual private-node revision/config/check references; the
// real Manager must still issue command owners and probe the native path.
type listXrayRuntimePreparation struct {
	self        *listXrayRuntimePreparation
	source      *XrayListRuntimeSource
	proof       *dataplane.NodeServiceProofReview
	compilation *DefaultRouteCompilation
}

func (r *XrayListRuntimeSource) prepare(ctx context.Context) (*listXrayRuntimePreparation, error) {
	if r == nil || r.self != r || xrayListSourceContext(ctx) != nil || r.closed.Load() {
		return nil, ErrXrayListSource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.currentLocked(ctx); err != nil {
		r.invalid = true
		return nil, err
	}
	proof, err := dataplane.ReviewNodeServiceProof(r.ctx, r.node, r.frozen, r.wan)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = proof.Close()
		}
	}()
	reference, err := proof.Observation(ctx)
	if err != nil || reference.NodeGeneration != r.node.Reference().NodeGeneration || reference.CompiledMaterialSHA256 != r.materialHash {
		return nil, errors.Join(ErrXrayListSource, err)
	}
	snapshot, err := r.scope.Observe(ctx)
	if err != nil {
		return nil, err
	}
	// Xray's private profiles live in this SAME actual NodeStore. Both
	// generations refer to that owner; no cache generation or constant fills
	// the compiler's checked-profile requirement.
	snapshot.NodeGeneration, snapshot.ProfileGeneration = reference.NodeGeneration, reference.NodeGeneration
	snapshot.Paths = map[string]DefaultRoutePath{r.service: {Selected: r.selected, Resolved: r.selected, ProbeURL: r.frozen.ProbeURL,
		ProfileDigest: reference.CompiledMaterialSHA256, ProofDigest: reference.ProofSHA256}}
	service := defaultRouteCloneCatalogService(r.frozen)
	route := dataplane.Route{ServiceID: r.service, ServiceName: service.Name, Selected: r.selected, Resolved: r.selected,
		CIDRs: slices.Clone(service.CIDRs), Sources: slices.Clone(r.expected.Services[r.service].Sources), ProbeURL: service.ProbeURL, ProbeService: &service}
	compilation, err := CompileDefaultRoutePolicy(r.expected, snapshot, []dataplane.Route{route}, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	// Bind only a nonempty finite native scope. Excluded/empty intent creates
	// no Xray preparation; the existing retirement coordinator owns that case.
	if len(compilation.rules) == 0 || compilation.LAN() == nil {
		return nil, ErrDefaultRouteCapability
	}
	if err := proof.Current(ctx); err != nil {
		return nil, err
	}
	if err := r.currentLocked(ctx); err != nil {
		r.invalid = true
		return nil, err
	}
	if err := r.scope.BindCompilation(ctx, compilation); err != nil {
		return nil, err
	}
	if err := proof.Current(ctx); err != nil {
		return nil, err
	}
	if err := r.currentLocked(ctx); err != nil {
		r.invalid = true
		return nil, err
	}
	p := &listXrayRuntimePreparation{source: r, proof: proof, compilation: compilation}
	p.self = p
	keep = true
	return p, nil
}

func (p *listXrayRuntimePreparation) current(ctx context.Context) error {
	if p == nil || p.self != p || p.source == nil || p.proof == nil || p.compilation == nil {
		return ErrXrayListSource
	}
	if err := p.source.Current(ctx); err != nil {
		return err
	}
	if err := p.proof.Current(ctx); err != nil {
		return err
	}
	if err := p.source.scope.ScopeCheck(ctx, p.compilation.LAN()); err != nil {
		return err
	}
	return p.source.Current(ctx)
}

func (p *listXrayRuntimePreparation) close() error {
	if p == nil || p.self != p || p.proof == nil {
		return ErrXrayListSource
	}
	return p.proof.Close() // original source/scope/App owners stay with caller
}

// acceptCommitted is the source portion of the original Xray assembly's
// Manager commit callback. Call only after SAME Store's successful unchanged-
// intent policy CAS, outside Store/scope callbacks, using the actual CAS times.
// It reads the postimage from that Store rather than accepting a caller DTO.
// This transition supplies neither runtime health nor command admission.
func (r *XrayListRuntimeSource) acceptCommitted(ctx context.Context, started, finished time.Time) error {
	if r == nil || r.self != r || xrayListSourceContext(ctx) != nil || r.closed.Load() {
		return ErrXrayListSource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.invalid || r.control == nil || r.registration == nil || r.cidrs == nil || r.node == nil {
		return ErrXrayListSource
	}
	deadline, _ := r.ctx.Deadline()
	c, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(r.ctx, cancel)
	defer func() { stop(); cancel() }()
	err := r.app.Operations.WithExclusiveContext(r.ctx, func() error {
		return r.app.Operations.WithExclusiveContext(c, func() error {
			if err := r.commitOwnersCurrent(); err != nil {
				return err
			}
			after := r.store.Get()
			if !defaultRouteCommittedConfig(r.expected, after, r.expected.NetworkPolicy, r.expected.Services, started, finished) {
				return ErrXrayListSource
			}
			if err := r.control.Current(c); err != nil {
				return err
			}
			if err := r.registration.Current(c); err != nil {
				return err
			}
			if err := r.cidrs.Current(c); err != nil {
				return err
			}
			wan, err := r.app.freshNetworkProfile(c)
			if err != nil || wan != r.wan || r.scope.facts.Identity != r.identity {
				return errors.Join(ErrXrayListSource, err)
			}
			material, err := r.currentNodeMaterial(c)
			if err != nil || material != r.materialHash {
				return errors.Join(ErrXrayListSource, err)
			}
			if err := r.cidrs.Current(c); err != nil {
				return err
			}
			if err := r.registration.Current(c); err != nil {
				return err
			}
			if err := r.commitOwnersCurrent(); err != nil {
				return err
			}
			if !reflect.DeepEqual(r.store.Get(), after) {
				return ErrXrayListSource
			}
			if err := r.control.Current(c); err != nil {
				return err
			}
			// The retained ScopeReview accepts this exact CAS and verifies the
			// original physical incarnation before our config reference advances.
			if err := r.scope.AcceptCommitted(c, after, started, finished); err != nil {
				return err
			}
			r.expected = after // defensive original Store clone, never a DTO
			return r.currentLocked(c)
		})
	})
	if err != nil {
		r.invalid = true
		return errors.Join(ErrXrayListSource, err)
	}
	return nil
}

// The only omitted currentApp predicate is its old config preimage. All other
// original owner identities remain mandatory during the sanctioned transition.
func (r *XrayListRuntimeSource) commitOwnersCurrent() error {
	if r.closed.Load() || r.app == nil || r.app.Store != r.store || r.app.Dataplane != r.manager || r.app.Nodes != r.nodes || r.app.Sources != r.sources ||
		r.app.CustomServices != r.custom || r.app.DNS != r.dns || r.app.SelfUpdateFiles != r.files || r.files.ControlRoot != r.root ||
		r.scope.self != r.scope || r.scope.app != r.app || r.scope.store != r.store ||
		applyReviewHash(r.app.catalogSnapshot()) != r.catalog || !wgListBaselineDNS(r.dns, r.service) {
		return ErrXrayListSource
	}
	return nil
}
