package app

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

type xrayAutonomyCandidate struct {
	self            *xrayAutonomyCandidate
	app             *App
	policy          autonomy.Policy
	spec            autonomy.Service
	before, planned config.Config
	route, profile  string
	committed       bool
}

// Compile candidate intent from the actual frozen Store image. Nothing is
// saved, no approval/revision is renewed, and node eligibility remains an
// actual service/WAN proof captured by the ordinary private source below.
func (a *App) xrayAutonomyCandidate(ctx context.Context, p autonomy.Policy, s autonomy.Service, before config.Config, profile, route string) (*xrayAutonomyCandidate, error) {
	if a == nil || a.Store == nil || !strings.HasPrefix(route, "xray:node-") || !reflect.DeepEqual(a.Store.Get(), before) || before.NetworkPolicy == nil || before.NetworkPolicy.Clients.Mode != "selected_devices" {
		return nil, ErrXrayListSource
	}
	for id, state := range before.Services {
		if id != s.ID && state.Enabled && selectedRoute(state) != "direct" {
			return nil, ErrDefaultRouteCapability
		}
	}
	planned, err := config.ReviewedAutonomyRouteCommitImage(before, s.ID, route, s.Sources, time.Now().UTC())
	if err != nil || !reflect.DeepEqual(planned.NetworkPolicy, before.NetworkPolicy) || !reflect.DeepEqual(planned.DefaultRouteConsent, before.DefaultRouteConsent) {
		return nil, errors.Join(ErrXrayListSource, err)
	}
	// Pure planning uses the original authority/revision. The actual one-use
	// Store writer alone will publish the final revision and applied timestamp.
	planned.Revision, planned.AppliedRevision, planned.LastAppliedAt = before.Revision, before.AppliedRevision, before.LastAppliedAt
	planned.AppliedServices = defaultRouteCloneServices(before.AppliedServices)
	s.Sources = slices.Clone(s.Sources)
	c := &xrayAutonomyCandidate{app: a, policy: autonomy.Clone(p), spec: s, before: before, planned: planned, route: route, profile: profile}
	c.self = c
	if err := c.current(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *xrayAutonomyCandidate) current(ctx context.Context) error {
	if c == nil || c.self != c || c.app == nil || c.app.Nodes == nil || !c.app.autonomyConsent(c.policy, c.spec) || c.app.autonomyDiskCurrent(ctx) != nil {
		return ErrXrayListSource
	}
	service, known := c.app.autonomyService(c.spec.ID)
	if !known || c.app.autonomyResourceGuard(ctx, c.policy, c.spec, c.app.Store.Get(), service) != nil {
		return ErrXrayListSource
	}
	wan, err := c.app.freshNetworkProfile(ctx)
	if err != nil || wan != c.profile {
		return errors.Join(ErrXrayListSource, err)
	}
	snapshot, err := c.app.Nodes.Snapshot(ctx, time.Now().UTC())
	if err != nil {
		return err
	}
	for _, node := range snapshot.Nodes {
		if c.route == "xray:"+node.ID && allowedAutonomyNode(c.policy, node, time.Now().UTC()) {
			return nil
		}
	}
	return ErrXrayListSource
}

func (r *XrayListRuntimeSource) acceptAutonomyCommitted(ctx context.Context, receipt *config.AutonomyRouteCommitReview) error {
	if r == nil || r.self != r || xrayListSourceContext(ctx) != nil || r.closed.Load() {
		return ErrXrayListSource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	fail := func(err error) error { r.invalid = true; return errors.Join(ErrXrayListSource, err) }
	if r.invalid || r.autonomy == nil || r.autonomy.committed || !receipt.MatchesStore(r.store) || r.commitOwnersCurrent() != nil {
		return fail(nil)
	}
	before, after, err := receipt.CommittedImages(ctx)
	if err != nil || !reflect.DeepEqual(before, r.expected) || selectedRoute(after.Services[r.service]) != r.selected || !slices.Equal(after.Services[r.service].Sources, r.autonomy.planned.Services[r.service].Sources) {
		return fail(err)
	}
	if err := r.scope.AcceptAutonomyCommitted(ctx, receipt); err != nil {
		return fail(err)
	}
	r.expected, r.autonomy.committed = after, true
	if err := r.currentLocked(ctx); err != nil {
		return fail(err)
	}
	from, to, err := receipt.CommittedImages(ctx)
	if err != nil || !reflect.DeepEqual(from, before) || !reflect.DeepEqual(to, after) {
		return fail(err)
	}
	return nil
}

// The actual selected-device producer lends its one original physical Review
// to the actual runtime. Round closure revokes forward reads; only the retained
// incarnation reader and original cleanup capabilities survive until joined
// retirement closes the binding. Models/DTOs cannot enter this constructor.
func (a *App) autonomyXrayScope(ctx context.Context) (*ListScopeBinding, error) {
	if a == nil || ctx == nil {
		return nil, ErrListScopeChanged
	}
	d, ok := ctx.Value(autonomyDeviceScopeKey{}).(*autonomyDeviceScope)
	if !ok || d == nil || d.self != d || d.app != a {
		return nil, ErrListScopeChanged
	}
	d.mu.Lock()
	if d.observer == nil || d.review == nil || d.borrowUsed || d.current(ctx) != nil {
		d.mu.Unlock()
		return nil, ErrListScopeChanged
	}
	d.borrowUsed, d.borrowed = true, true
	d.mu.Unlock()
	var once sync.Once
	var closeErr error
	release := func() error {
		once.Do(func() {
			d.mu.Lock()
			defer d.mu.Unlock()
			d.borrowed = false
			if d.closed {
				d.closeErr = d.review.Close()
			}
			closeErr = d.closeErr
		})
		return closeErr
	}
	b, err := newListScopeBinding(ctx, a, func(c context.Context, selection physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.Snapshot, func() error, error) {
		want, err := selection(c)
		if err != nil || !reflect.DeepEqual(want, d.facts.Selection) || !reflect.DeepEqual(d.review.Snapshot(), d.facts) {
			return nil, nil, nil, errors.Join(ErrListScopeChanged, err)
		}
		return func(c context.Context) error { return d.observer.Verify(c, d.review) }, d.review.Snapshot, release, nil
	})
	if err != nil {
		return nil, errors.Join(err, release())
	}
	b.originalPhysicalObserver, b.originalPhysicalReview = d.observer, d.review
	b.verifyCleanupPhysical = func(c context.Context) error { return d.observer.VerifyRetainedIncarnation(c, d.review) }
	return b, nil
}

func (a *App) applyManagedAutonomyXray(ctx context.Context, p autonomy.Policy, s autonomy.Service, before config.Config, profile, route string) (resultErr error) {
	a.managedXraySelectedTCPListMu.Lock()
	r := a.managedXraySelectedTCPList
	a.managedXraySelectedTCPListMu.Unlock()
	if r == nil || !r.original() || !reflect.DeepEqual(before.NetworkPolicy, before.AppliedNetworkPolicy) {
		return ErrXrayListSource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending != nil || r.preparing != nil || r.stopped != nil {
		return ErrXrayListSource
	}
	if r.active != nil && (r.active.source == nil || r.active.source.service != s.ID || r.active.source.selected != selectedRoute(before.Services[s.ID])) {
		return ErrXrayListSource
	}
	c, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		return err
	}
	owned := true
	defer func() {
		if owned {
			release()
		}
	}()
	candidate, err := a.xrayAutonomyCandidate(c, p, s, before, profile, route)
	if err != nil {
		return err
	}
	e := &managedXraySelectedTCPListExecution{runtime: r, previous: r.active}
	e.self = e
	r.preparing = e
	keep := false
	defer func() {
		r.preparing = nil
		if !keep {
			resultErr = errors.Join(resultErr, e.close())
		}
	}()
	if _, err := e.prepare(c, s.ID, candidate); err != nil {
		return err
	}
	e.lanAdmission, err = r.manager.ReviewLANPolicyCommandAdmission(c, r.policy.gate, r.policy.inventory, r.policy.control)
	if err != nil {
		return err
	}
	cleanup, err := r.policy.control.ReviewExclusiveCleanup(c)
	if err != nil {
		return err
	}
	c, closeOperation, err := r.operation(c, e, cleanup)
	if err != nil {
		return err
	}
	defer func() {
		if owned {
			closeOperation()
		}
	}()
	if e.previous == nil {
		c, err = e.material.BindExecution(c, r.policy.panel, e.plan, r.policy.inventory, r.policy.gate, r.policy.checks, e.committedGuard, e.cleanupGuard)
	} else {
		c, err = e.material.BindReplacementExecution(c, r.policy.panel, e.previous.plan, e.plan, r.policy.inventory, r.policy.gate, r.policy.checks, e.committedGuard, e.cleanupGuard)
	}
	if err != nil {
		return err
	}
	c = dataplane.WithReviewGuard(c, e.guard)
	store := e.source.store // The actual original source owner alone writes CAS.
	execution, applyErr := a.applyDataplane(c, e.plan, func() (func() error, error) {
		if err := e.guard(c); err != nil {
			return nil, err
		}
		if a.Store != store || !reflect.DeepEqual(store.Get(), before) {
			return nil, dataplane.ErrReviewChanged
		}
		undo, receipt, err := store.ApplyAutonomyRouteReviewedWithRollback(s.ID, route, s.Sources, before.Revision)
		if err != nil {
			return undo, err
		}
		wrappedUndo := func() error {
			if err := undo(); err != nil {
				return err
			}
			check, cancel := context.WithTimeout(context.WithoutCancel(c), defaultDataplaneApplyTimeout)
			defer cancel()
			_, restored, err := receipt.RestoredImages(check)
			if err != nil || !reflect.DeepEqual(restored, before) {
				return errors.Join(dataplane.ErrReviewChanged, err)
			}
			return nil
		}
		if err := e.source.acceptAutonomyCommitted(c, receipt); err != nil {
			return wrappedUndo, err
		}
		return wrappedUndo, e.guard(c)
	})
	if applyErr != nil {
		if r.manager.HasPendingManagedXraySelectedTCP() {
			e.pendingContext, e.pendingCloseOperation, e.pendingRelease = c, closeOperation, release
			r.pending = e
			owned, keep = false, true
			a.Operations.FenceJournal()
		}
		return &autonomyApplyFailure{Plan: e.plan, Execution: execution, Cause: applyErr}
	}
	if execution.State != "committed" {
		return ErrXrayListSource
	}
	if e.previous != nil {
		if err := e.previous.close(); err != nil {
			e.pendingReplacementComplete = true
			e.pendingContext, e.pendingCloseOperation, e.pendingRelease = c, closeOperation, release
			r.pending = e
			owned, keep = false, true
			a.Operations.FenceJournal()
			return err
		}
	}
	e.previous = nil
	r.active = e
	keep = true
	return nil
}
