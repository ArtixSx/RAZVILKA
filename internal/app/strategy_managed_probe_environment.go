package app

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"sync"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

// Comparison owner for one explicit router-origin check. It supplies no
// process, packet, rule or LAN admission. The actual managed consumer retains
// those owners independently through its confirmed cleanup.
type managedStrategyProbeEnvironment struct {
	self       *managedStrategyProbeEnvironment
	mu         sync.Mutex
	app        *App
	store      *config.Store
	components *components.Manager
	control    *operationgate.ControlEpochReview
	runtime    *components.ManagedNFQWSRuntimeLease
	descriptor components.NFQWSRuntimeDescriptor
	expected   config.Config
	catalog    string
	service    catalog.Service
	scope      strategylab.CandidateProbeScope
	networkID  string
	policyHash string
	retired    bool
	closed     bool
	fresh      func(context.Context) (string, error)
}

func newManagedStrategyProbeEnvironment(ctx context.Context, a *App, control *operationgate.ControlEpochReview, runtime *components.ManagedNFQWSRuntimeLease, service catalog.Service, scope strategylab.CandidateProbeScope) (*managedStrategyProbeEnvironment, error) {
	criteria, criteriaErr := strategylab.ManagedProbeCriteriaDigest(service)
	if criteriaErr != nil || a == nil || a.Store == nil || a.Components == nil || a.StrategyLab == nil || control == nil || runtime == nil || ctx == nil || ctx.Err() != nil || scope.Target.ServiceID != service.ID || scope.Target.ProbeURL != service.ProbeURL || scope.CriteriaDigest != criteria {
		return nil, dataplane.ErrReviewChanged
	}
	r := &managedStrategyProbeEnvironment{app: a, store: a.Store, components: a.Components, control: control, runtime: runtime, descriptor: runtime.Descriptor(), expected: a.Store.Get(), catalog: applyReviewHash(a.catalogSnapshot()), service: defaultRouteCloneCatalogService(service), scope: scope, fresh: a.FreshProfile}
	r.self = r
	if r.fresh == nil {
		r.fresh = func(c context.Context) (string, error) {
			profile, err := systemprobe.FreshWANProfile(c)
			return profile.ID, err
		}
	}
	var err error
	r.networkID, err = r.fresh(ctx)
	if err != nil || !systemprobe.ValidWANProfileID(r.networkID) {
		return nil, errors.Join(dataplane.ErrReviewChanged, err)
	}
	r.policyHash = applyReviewHash(r.expected)
	if err := r.Current(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *managedStrategyProbeEnvironment) sourceCurrent(ctx context.Context) error {
	if r == nil || r.self != r || ctx == nil || ctx.Err() != nil || r.app == nil || r.store == nil || r.app.Store != r.store || r.app.Components != r.components || applyReviewHash(r.app.catalogSnapshot()) != r.catalog {
		return dataplane.ErrReviewChanged
	}
	u, err := url.Parse(r.scope.Target.ProbeURL)
	criteria, criteriaErr := strategylab.ManagedProbeCriteriaDigest(r.service)
	if err != nil || criteriaErr != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Port() != "" && u.Port() != "443" || r.scope.Target.Protocol != "tcp" || r.scope.Target.IPFamily != "ipv4" || !r.scope.Address.Is4() || !r.scope.Address.IsGlobalUnicast() || r.scope.Address.IsPrivate() || r.scope.CriteriaDigest != criteria {
		return dataplane.ErrReviewChanged
	}
	known := false
	for _, service := range r.app.catalogSnapshot().Services {
		if service.ID == r.service.ID && reflect.DeepEqual(service, r.service) {
			known = true
		}
	}
	if !known || r.fresh == nil {
		return dataplane.ErrReviewChanged
	}
	checkWAN := func() error {
		fresh, err := r.fresh(ctx)
		if err != nil || !systemprobe.ValidWANProfileID(fresh) || fresh != r.networkID {
			return errors.Join(dataplane.ErrReviewChanged, err)
		}
		return ctx.Err()
	}
	// The configured WAN observer may read Store. Never invoke it while the
	// Store's exclusion observation holds its lock.
	if err := checkWAN(); err != nil {
		return err
	}
	checkExclusions := func() error {
		return r.store.WithResourceExclusionObservation(ctx, r.expected, func(exclusions config.EffectiveExclusionSet) error {
			denied, err := exclusions.Matches(config.ResourceTarget{ServiceID: r.service.ID, Domain: u.Hostname(), Address: r.scope.Address})
			if err != nil || denied {
				return errors.Join(dataplane.ErrReviewChanged, err)
			}
			return ctx.Err()
		})
	}
	if err := checkExclusions(); err != nil {
		return err
	}
	if err := checkWAN(); err != nil {
		return err
	}
	if r.app.Store != r.store || r.app.Components != r.components || applyReviewHash(r.app.catalogSnapshot()) != r.catalog {
		return dataplane.ErrReviewChanged
	}
	return checkExclusions()
}

func (r *managedStrategyProbeEnvironment) Current(ctx context.Context) error {
	if r == nil || r.self != r || r.control == nil {
		return dataplane.ErrReviewChanged
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.components == nil || r.runtime == nil {
		return dataplane.ErrReviewChanged
	}
	if err := errors.Join(r.control.Current(ctx), r.sourceCurrent(ctx)); err != nil {
		return err
	}
	if !r.retired {
		if err := r.runtime.Check(ctx); err != nil {
			return err
		}
		if !reflect.DeepEqual(r.runtime.Descriptor(), r.descriptor) {
			return dataplane.ErrReviewChanged
		}
	} else {
		// A completed proof does not hold the component writer lock forever.
		// Only the same configured Manager may freshly verify its generation;
		// this short read grants no process ownership or future Apply.
		descriptor, err := r.components.ObserveCurrentManagedNFQWSRuntime(ctx)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(descriptor, r.descriptor) {
			return dataplane.ErrReviewChanged
		}
	}
	return errors.Join(r.control.Current(ctx), r.sourceCurrent(ctx))
}

// The App calls this only after the concrete consumer's opaque completion has
// confirmed resource removal and successfully closed this exact runtime lease.
func (r *managedStrategyProbeEnvironment) runtimeRetired() error {
	if r == nil || r.self != r {
		return dataplane.ErrReviewChanged
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.retired || r.runtime == nil || r.runtime.Descriptor().ReceiptID != "" {
		return dataplane.ErrReviewChanged
	}
	r.retired = true
	return nil
}
