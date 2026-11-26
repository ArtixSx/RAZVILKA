package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// DefaultRouteDependencies are explicit shared-owner boundaries, not runtime
// capability booleans. Observe checks actual profile/node proofs and the
// durable control owner. BindIngress compiles exact iif and negative MAC gates
// in the existing adapters/receipt protocol, and refuses unsupported coverage.
// Commit must use Store.CommitNetworkPolicyWithRollback for the same Store.
// Missing dependencies can never release the legacy executor guard.
type DefaultRouteDependencies struct {
	Observe     func(context.Context) (DefaultRouteSnapshot, error)
	BindIngress func(context.Context, *DefaultRouteCompilation, dataplane.Input) (dataplane.Input, error)
	Commit      func(config.Config, *config.NetworkPolicy, map[string]config.ServiceState) (func() error, error)
}

// DefaultRouteFlowPolicy is the executable bridge's immutable input. A bridge
// must select outbound before forwarding a connection, preserve baseline on
// a list miss, and reject incomplete domain visibility/UDP coverage.
// DNS-derived IP labels must never be used as FlowName authority.
type DefaultRouteFlowPolicy struct {
	Config   config.Config
	Snapshot DefaultRouteSnapshot
	Services []dataplane.Route
}

// DefaultRouteFlowBridge uses the SAME registered transactional adapter and
// Manager.Apply. Compose is read-only; Snapshot/Stage/Activate/Health/Commit/
// Rollback remain the existing Adapter protocol. No DNS scheduler or second
// execution journal belongs in this bridge. No bridge is claimed implemented
// by this IP-only checkpoint.
type DefaultRouteFlowBridge interface {
	dataplane.Adapter
	ComposeDefaultRoute(context.Context, DefaultRouteFlowPolicy) (dataplane.Input, error)
}

type DefaultRouteExecutor struct {
	app  *App
	deps DefaultRouteDependencies
}

// NewDefaultRouteExecutor creates a consumer of actual registered adapters.
// CORE installs the shared bindings after their own capability checks; this
// constructor never registers/replaces an adapter or touches the network.
func NewDefaultRouteExecutor(a *App, deps DefaultRouteDependencies) (*DefaultRouteExecutor, error) {
	if a == nil || a.Store == nil || a.Dataplane == nil || deps.Observe == nil || deps.BindIngress == nil || deps.Commit == nil {
		return nil, fmt.Errorf("%w: shared ingress/control/CAS bindings missing", ErrDefaultRouteCapability)
	}
	return &DefaultRouteExecutor{app: a, deps: deps}, nil
}

type DefaultRouteReview struct {
	mu           sync.Mutex
	used         bool
	owner        *DefaultRouteExecutor
	cfg          config.Config
	compilation  *DefaultRouteCompilation
	plan         dataplane.Plan
	committed    dataplane.Plan
	hasCommitted bool
	catalogHash  string
	digest       string
}

func (r *DefaultRouteReview) Digest() string { return r.digest }
func (r *DefaultRouteReview) Plan() dataplane.Plan {
	// A presentation must not be able to edit the reviewed execution object.
	return defaultRouteClonePlan(r.plan)
}

// Review takes trusted resolved definitions from the existing application
// route builder, not route/profile/proof fields from an HTTP request.
func (e *DefaultRouteExecutor) Review(ctx context.Context, services []dataplane.Route) (*DefaultRouteReview, error) {
	ctx, release, err := e.app.privateExclusiveOperation(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	cfg := e.app.Store.Get()
	snapshot, err := e.deps.Observe(ctx)
	if err != nil {
		return nil, err
	}
	c, err := CompileDefaultRoutePolicy(cfg, snapshot, services, time.Now())
	if err != nil {
		return nil, err
	}
	// The generic Route carries no port coverage. Only the separate actual
	// managed owner may pair these exact tuples with its scoped NFQUEUE spec.
	for _, rule := range c.rules {
		if rule.Route == "nfqws2" {
			return nil, fmt.Errorf("%w: managed NFQWS requires its exact traffic consumer", ErrDefaultRouteCapability)
		}
	}
	previous, exists, err := e.app.Dataplane.Committed()
	if err != nil {
		return nil, err
	}
	if exists && (previous.State != "committed" || previous.Revision != cfg.AppliedRevision || previous.DNS != nil || previous.SuspendDNS) {
		return nil, fmt.Errorf("%w: prior runtime/DNS requires matching review", ErrDefaultRouteCapability)
	}
	input := e.input(c, cfg)
	if exists {
		desired := map[string]bool{}
		if input.LAN != nil {
			desired[dataplane.NetworkPolicyAdapterID] = true
		}
		for _, route := range input.Routes {
			desired[dataplane.AdapterID(route.Resolved)] = true
		}
		for _, id := range previous.Adapters {
			if !desired[id] {
				input.RetiringAdapters = append(input.RetiringAdapters, id)
				// Empty list plans still retire actual previously registered
				// owners. Build checks this capability; Manager additionally
				// requires their existing scoped deactivation protocol.
				capable := e.app.Dataplane.Capable(id)
				input.Engines = append(input.Engines, dataplane.Engine{ID: id, Installed: capable, Configured: capable, Activatable: capable})
			}
		}
		sort.Slice(input.Engines, func(i, j int) bool { return input.Engines[i].ID < input.Engines[j].ID })
	}
	baseInput := defaultRouteCloneInput(input)
	input, err = e.deps.BindIngress(ctx, c, defaultRouteCloneInput(input))
	if err != nil {
		return nil, err
	}
	if !defaultRouteBoundInput(baseInput, input) {
		return nil, fmt.Errorf("%w: shared binding changed reviewed routes", ErrDefaultRouteCapability)
	}
	plan, err := dataplane.BuildAt(input, time.Now())
	if err != nil {
		return nil, err
	}
	if !plan.Ready {
		return nil, fmt.Errorf("%w: adapter preflight blocked", ErrDefaultRouteCapability)
	}
	// Existing adapter receipts share this complete identity; a policy,
	// profile, consent or control transition cannot reuse an old transaction.
	plan.Digest = defaultRouteDigest(struct{ Plan, Policy string }{plan.Digest, c.digest})
	plan.PlanID, err = newDefaultRouteAttemptID()
	if err != nil {
		return nil, err
	}
	r := &DefaultRouteReview{owner: e, cfg: cfg, compilation: c, plan: defaultRouteClonePlan(plan), committed: previous, hasCommitted: exists, catalogHash: applyReviewHash(e.app.catalogSnapshot())}
	r.digest = defaultRouteDigest(struct{ Plan, Config, Catalog string }{plan.Digest, applyReviewHash(cfg), r.catalogHash})
	if err := e.guard(ctx, r, cfg, true); err != nil {
		return nil, err
	}
	return r, nil
}

func (e *DefaultRouteExecutor) input(c *DefaultRouteCompilation, cfg config.Config) dataplane.Input {
	input := dataplane.Input{NFQWSFirstStartRecipe: cfg.AppliedNFQWSFirstStartRecipe, LAN: c.LAN(), Revision: cfg.Revision + 1, NetworkProfileID: c.snapshot.Scope.NetworkID, SafeMode: cfg.SafeMode}
	if input.LAN != nil {
		gateCapable := e.app.Dataplane.Capable(dataplane.NetworkPolicyAdapterID)
		input.Engines = append(input.Engines, dataplane.Engine{ID: dataplane.NetworkPolicyAdapterID, Installed: gateCapable, Configured: gateCapable, Activatable: gateCapable})
	}
	if e.app.DataplaneHost != nil {
		input.Host = e.app.DataplaneHost()
	} else {
		input.Host = dataplane.DiscoverHost()
	}
	// One route per source/ingress/path permits exact binding by CORE without
	// an accidental Cartesian union between two different LAN segments.
	groups := map[string]*dataplane.Route{}
	catalogServices := e.app.catalogSnapshot().Services
	for _, rule := range c.rules {
		key := rule.ServiceID + "\x00" + rule.Ingress + "\x00" + rule.Source.String() + "\x00" + rule.Route
		route, ok := groups[key]
		if !ok {
			path := c.snapshot.Paths[rule.ServiceID]
			id := "network-" + defaultRouteDigest(key)[:16]
			route = &dataplane.Route{
				WireGuardProfileRevision: path.WireGuardProfileRevision,
				LogicalServiceID:         rule.ServiceID,
				ServiceID:                id, ServiceName: rule.ServiceID, Selected: path.Selected, Resolved: path.Resolved,
				Sources: []string{rule.Source.String()}, Ingress: []string{rule.Ingress}, ProbeURL: path.ProbeURL,
				NetworkPolicyGeneration: c.digest, NetworkPolicyRole: rule.Origin,
			}
			if rule.Origin == "override" {
				for _, service := range catalogServices {
					if service.ID == rule.ServiceID {
						frozen := defaultRouteCloneCatalogService(service)
						route.ProbeService = &frozen
						break
					}
				}
			}
			groups[key] = route
		}
		route.CIDRs = append(route.CIDRs, rule.Destination.String())
	}
	for _, route := range groups {
		input.Routes = append(input.Routes, *route)
	}
	sort.Slice(input.Routes, func(i, j int) bool { return input.Routes[i].ServiceID < input.Routes[j].ServiceID })
	ids := map[string]bool{}
	for _, route := range input.Routes {
		ids[dataplane.AdapterID(route.Resolved)] = true
	}
	for id := range ids {
		input.Engines = append(input.Engines, dataplane.Engine{ID: id, Installed: true, Configured: true, Activatable: e.app.Dataplane.Capable(id), Canary: e.app.Dataplane.CanaryCapable(id)})
	}
	sort.Slice(input.Engines, func(i, j int) bool { return input.Engines[i].ID < input.Engines[j].ID })
	if e.app.EngineLab != nil {
		var adapters []string
		for id := range ids {
			adapters = append(adapters, id)
		}
		slices.Sort(adapters)
		for _, conflict := range e.app.EngineLab.Inspect().ApplyConflicts(adapters) {
			input.ResourceConflicts = append(input.ResourceConflicts, dataplane.ResourceConflict{Kind: conflict.Kind, Value: conflict.Value, Engines: conflict.Engines, SystemUse: conflict.SystemUse})
		}
	}
	return input
}

func (e *DefaultRouteExecutor) guard(ctx context.Context, r *DefaultRouteReview, expected config.Config, checkCommitted bool) error {
	return e.app.Operations.WithExclusiveContext(ctx, func() error {
		return e.guardUnderOperation(ctx, r, expected, checkCommitted)
	})
}

func (e *DefaultRouteExecutor) guardUnderOperation(ctx context.Context, r *DefaultRouteReview, expected config.Config, checkCommitted bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := e.observeConfig(ctx, expected); err != nil {
		return err
	}
	if applyReviewHash(e.app.catalogSnapshot()) != r.catalogHash {
		return dataplane.ErrReviewChanged
	}
	snapshot, err := e.deps.Observe(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	if snapshot.Stopped || now.Before(snapshot.Scope.ObservedAt) || !now.Before(snapshot.Scope.FreshUntil) || snapshot.Scope.FreshUntil.Sub(snapshot.Scope.ObservedAt) > 2*time.Minute || defaultRouteDigest(defaultRouteIdentity(snapshot)) != defaultRouteDigest(defaultRouteIdentity(r.compilation.snapshot)) {
		return dataplane.ErrReviewChanged
	}
	if checkCommitted {
		previous, exists, err := e.app.Dataplane.Committed()
		if err != nil || exists != r.hasCommitted || exists && !reflect.DeepEqual(previous, r.committed) {
			return dataplane.ErrReviewChanged
		}
	}
	// Observe can perform bounded profile/control reads; a disk replacement
	// during that work must not escape this final guard.
	return e.observeConfig(ctx, expected)
}

func (e *DefaultRouteExecutor) observeConfig(ctx context.Context, expected config.Config) error {
	current := e.app.Store.Get()
	if current.SafeMode || current.ServiceControl.Stopped || !reflect.DeepEqual(current, expected) {
		return dataplane.ErrReviewChanged
	}
	// Bounded disk observation borrows no writer lease. Its callback must
	// never call Store/Observe or hold admission through adapter effects.
	wanted, err := config.EffectiveResourceExclusions(expected.NetworkPolicy)
	if err != nil {
		return errors.Join(dataplane.ErrReviewChanged, err)
	}
	if err := e.app.Store.WithResourceExclusionObservation(ctx, expected, func(observed config.EffectiveExclusionSet) error {
		if observed.PolicyRevision != wanted.PolicyRevision || observed.Revision != wanted.Revision || observed.Digest != wanted.Digest {
			return dataplane.ErrReviewChanged
		}
		return nil
	}); err != nil {
		return errors.Join(dataplane.ErrReviewChanged, err)
	}
	// Same-revision legacy changes also invalidate the full reviewed image.
	if !reflect.DeepEqual(e.app.Store.Get(), expected) {
		return dataplane.ErrReviewChanged
	}
	return nil
}

// Execute owns application admission through the complete existing Apply,
// including detached bounded rollback/readback. A rejected or used review
// never starts an adapter, and an unknown rollback permanently fences the app.
// Actual process/kernel starts must additionally use CORE's short effect
// admission; a read-only Observe call is not that admission.
func (e *DefaultRouteExecutor) Execute(ctx context.Context, r *DefaultRouteReview, digest string) (dataplane.Execution, error) {
	if r == nil || r.owner != e || digest != r.digest {
		return dataplane.Execution{}, dataplane.ErrReviewChanged
	}
	ctx, release, err := e.app.privateExclusiveOperation(ctx)
	if err != nil {
		return dataplane.Execution{}, err
	}
	defer release()
	r.mu.Lock()
	if r.used {
		r.mu.Unlock()
		return dataplane.Execution{}, dataplane.ErrReviewChanged
	}
	r.used = true
	r.mu.Unlock()
	if err := e.guard(ctx, r, r.cfg, true); err != nil {
		return dataplane.Execution{}, err
	}
	expected := r.cfg
	var expectedMu sync.RWMutex
	guard := func(c context.Context) error {
		expectedMu.RLock()
		currentExpected := expected
		expectedMu.RUnlock()
		return e.guard(c, r, currentExpected, false)
	}
	ctx = dataplane.WithReviewGuard(ctx, guard)
	execution, err := e.app.applyDataplane(ctx, defaultRouteClonePlan(r.plan), func() (func() error, error) {
		if err := guard(ctx); err != nil {
			return nil, err
		}
		// Store.Get provides its exact defensive representation. A JSON
		// round trip loses empty omitempty maps and is not a full CAS preimage.
		commitConfig := e.app.Store.Get()
		if !reflect.DeepEqual(commitConfig, r.cfg) {
			return nil, dataplane.ErrReviewChanged
		}
		services := defaultRouteCloneServices(r.cfg.Services)
		commitStarted := time.Now()
		undo, err := e.deps.Commit(commitConfig, r.compilation.Policy(), services)
		commitFinished := time.Now()
		if err != nil {
			return undo, err
		}
		committed := e.app.Store.Get()
		if !defaultRouteCommittedConfig(r.cfg, committed, r.compilation.policy, services, commitStarted, commitFinished) {
			return undo, dataplane.ErrReviewChanged
		}
		if err := e.observeConfig(ctx, committed); err != nil {
			return undo, err
		}
		// Publish only the verified immutable postimage to guards that an
		// adapter may call concurrently while its owned workers are joined.
		expectedMu.Lock()
		expected = committed
		expectedMu.Unlock()
		return undo, nil
	})
	// The manager reports missing rollback proof separately from errors in
	// restoration. Neither grants permission to try another default candidate.
	if err != nil && execution.State == "rolled-back" && !execution.RollbackVerified && dataplaneExecutionMutated(execution) {
		e.app.Operations.FenceJournal()
	}
	if errors.Is(err, dataplane.ErrExecutionJournal) {
		e.app.Operations.FenceJournal()
	}
	return execution, err
}

func defaultRouteCommittedConfig(before, after config.Config, p *config.NetworkPolicy, services map[string]config.ServiceState, started, finished time.Time) bool {
	at, err := time.Parse(time.RFC3339, after.LastAppliedAt)
	// Bind the only clock-derived field independently of the shared image
	// helper; otherwise an old/future timestamp could masquerade as this commit.
	if err != nil || started.IsZero() || finished.Before(started) || after.LastAppliedAt != at.UTC().Format(time.RFC3339) ||
		at.Before(started.UTC().Truncate(time.Second)) || at.After(finished.UTC().Truncate(time.Second)) {
		return false
	}
	// The Store and this checker share CORE's exact sanctioned transition:
	// normalized applied states plus fences for changed/removed service policy.
	expected, err := config.ReviewedNetworkPolicyCommitImage(before, p, services, at)
	return err == nil && reflect.DeepEqual(expected, after)
}

func defaultRouteCloneServices(in map[string]config.ServiceState) map[string]config.ServiceState {
	result := make(map[string]config.ServiceState, len(in))
	for id, state := range in {
		state.Sources = slices.Clone(state.Sources)
		result[id] = state
	}
	return result
}

func defaultRouteClonePlan(p dataplane.Plan) dataplane.Plan {
	// These are trusted bounded structs; serialization gives every nested
	// owner (including DNS probe slices) an independent copy.
	data, _ := json.Marshal(p)
	var result dataplane.Plan
	_ = json.Unmarshal(data, &result)
	return result
}

func defaultRouteCloneInput(p dataplane.Input) dataplane.Input {
	data, _ := json.Marshal(p)
	var result dataplane.Input
	_ = json.Unmarshal(data, &result)
	return result
}

func defaultRouteCloneConfig(cfg config.Config) config.Config {
	data, _ := json.Marshal(cfg)
	var result config.Config
	_ = json.Unmarshal(data, &result)
	return result
}

// The binder may not clear a route, add DNS redirection, widen a source,
// change exact ingress/generation/role, weaken preflight or retire an unrelated
// owner. The composer already binds CORE's reviewed route metadata.
func defaultRouteBoundInput(before, after dataplane.Input) bool {
	return reflect.DeepEqual(before, after)
}
