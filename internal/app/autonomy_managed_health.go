package app

import (
	"context"
	"errors"
	"reflect"
	"strings"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func autonomyManagedXraySelected(cfg config.Config, plan dataplane.Plan, route string) bool {
	return plan.LAN != nil && plan.LAN.Mode == dataplane.LANPolicyXraySelectedTCPMode ||
		cfg.AppliedNetworkPolicy != nil && strings.HasPrefix(route, "xray:node-")
}

// A comparison of the actual compiler's frozen output. LogicalServiceID is
// the saved service; ServiceID is its private per-ingress compiler identity.
// Configured sources can be wider than the single compiled selected device.
// Neither comparison data nor a successful match grants runtime authority.
func autonomyManagedXrayCompiledMatches(plan dataplane.Plan, compilation *DefaultRouteCompilation, service catalog.Service, current string) bool {
	if compilation == nil || plan.LAN == nil || plan.LAN.Mode != dataplane.LANPolicyXraySelectedTCPMode ||
		!reflect.DeepEqual(plan.LAN, compilation.LAN()) || plan.NetworkProfileID != compilation.snapshot.Scope.NetworkID || len(plan.Routes) != 1 || len(plan.LAN.Ingress) != 1 {
		return false
	}
	route, ingress := plan.Routes[0], plan.LAN.Ingress[0]
	frozen, err := dataplane.FrozenProbeService(route)
	return route.LogicalServiceID == service.ID && route.Selected == current && route.Resolved == current &&
		err == nil && reflect.DeepEqual(frozen, service) && route.ProbeURL == service.ProbeURL &&
		reflect.DeepEqual(route.CIDRs, service.CIDRs) && reflect.DeepEqual(route.Sources, ingress.Sources) &&
		reflect.DeepEqual(route.Ingress, []string{ingress.Interface}) && route.NetworkPolicyGeneration == compilation.Digest() && route.NetworkPolicyRole == "override"
}

// Manager publishes documentary phase/evidence after applying the immutable
// intent. Compare that intent separately, and require the actual original
// Manager's complete current committed image. Neither comparison grants any
// retained owner, process, health or Apply admission.
func autonomyManagedXrayJournalMatches(manager *dataplane.Manager, actual, original dataplane.Plan, appliedRevision uint64) bool {
	if manager == nil || actual.State != "committed" || actual.Revision != appliedRevision || !sameManagedXrayAppliedPlan(actual, original) {
		return false
	}
	current, exists, err := manager.Committed()
	return err == nil && exists && reflect.DeepEqual(current, actual)
}

// Call with the original runtime lock held. The journal plan must be the SAME
// retained execution and the actual Store must still contain its full image.
func (r *ManagedXraySelectedTCPListRuntime) autonomyCommittedMatches(cfg config.Config, plan dataplane.Plan, id, current string) bool {
	if !r.original() || r.pending != nil || r.preparing != nil || r.active == nil {
		return false
	}
	e := r.active
	if e.self != e || e.runtime != r || e.scope == nil || e.source == nil || e.source.self != e.source || e.preparation == nil ||
		e.preparation.self != e.preparation || e.preparation.source != e.source || e.scope != e.source.scope ||
		!autonomyManagedXrayJournalMatches(r.manager, plan, e.plan, cfg.AppliedRevision) || !cfg.AppliedServices[id].Enabled || selectedRoute(cfg.AppliedServices[id]) != current {
		return false
	}
	source := e.source
	source.mu.Lock()
	defer source.mu.Unlock()
	return !source.invalid && source.service == id && source.selected == current && source.commitOwnersCurrent() == nil &&
		reflect.DeepEqual(source.expected, cfg) && reflect.DeepEqual(source.store.Get(), cfg) &&
		autonomyManagedXrayCompiledMatches(plan, e.preparation.compilation, source.frozen, current)
}

func (a *App) autonomyManagedXrayCommittedMatches(cfg config.Config, plan dataplane.Plan, id, current string) bool {
	a.managedXraySelectedTCPListMu.Lock()
	r := a.managedXraySelectedTCPList
	a.managedXraySelectedTCPListMu.Unlock()
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.autonomyCommittedMatches(cfg, plan, id, current)
}

// The managed branch uses the original App/Manager retained reader. A missing
// owner never falls back to legacy dispatch or publishes healthy from PASS
// alone. Its native listener/process/COMMON/writer and physical checks remain
// inside currentLocked, under the SAME current exclusive App operation.
func (a *App) checkAutonomyCommittedNodeHealth(ctx context.Context, cfg config.Config, plan dataplane.Plan, id, current string, guard func(context.Context) error) error {
	if err := guard(ctx); err != nil {
		return err
	}
	var err error
	if autonomyManagedXraySelected(cfg, plan, current) {
		a.managedXraySelectedTCPListMu.Lock()
		r := a.managedXraySelectedTCPList
		a.managedXraySelectedTCPListMu.Unlock()
		if r == nil {
			return errors.Join(ErrXrayListSource, guard(ctx))
		}
		r.mu.Lock()
		if !r.autonomyCommittedMatches(cfg, plan, id, current) {
			err = ErrXrayListSource
		} else {
			err = r.currentLocked(ctx)
			if !r.autonomyCommittedMatches(cfg, plan, id, current) {
				err = errors.Join(err, ErrXrayListSource)
			}
		}
		r.mu.Unlock()
	} else {
		err = a.Dataplane.CheckCommittedNodeHealth(dataplane.WithReviewGuard(ctx, guard), plan)
	}
	return errors.Join(err, guard(ctx))
}
