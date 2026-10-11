package app

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

var errComponentServiceProofUnconfirmed = errors.New("managed component service proof is unconfirmed")

func managedComponentForPlan(plan dataplane.Plan) string {
	if managedWGPlan(plan) {
		return dataplane.AdapterID(plan.Routes[0].Resolved)
	}
	if plan.LAN != nil {
		switch plan.LAN.Mode {
		case dataplane.LANPolicyNFQWSDirectMode:
			return "nfqws2"
		case dataplane.LANPolicyXraySelectedTCPMode:
			return "xray"
		}
	}
	return ""
}

// The actual caller already owns admission. This read validates that SAME
// lease and issues only an in-call original runtime operation, never a second
// admission or a borrowed restore scope. Structural ownership does not prove
// selected-client service reachability or accept a component update.
func (a *App) observeManagedComponentRuntime(ctx context.Context, expected dataplane.Plan, component string) (bool, error) {
	ownerComponent := managedComponentForPlan(expected)
	if ownerComponent == "" {
		return false, nil
	}
	if component != ownerComponent || a == nil || a.Store == nil || a.Dataplane == nil || ctx == nil {
		return true, errComponentRuntimeUnconfirmed
	}
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cfg := a.Store.Get()
	verify := func() error {
		if err := a.Operations.WithExclusiveContext(c, func() error { return nil }); err != nil {
			return err
		}
		if c.Err() != nil || cfg.SafeMode || cfg.ServiceControl.Stopped || expected.State != "committed" || expected.SafeMode || expected.Noop || expected.Revision != cfg.AppliedRevision || !reflect.DeepEqual(cfg, a.Store.Get()) {
			return errComponentRuntimeUnconfirmed
		}
		actual, found, err := a.Dataplane.Committed()
		if err != nil || !found || !reflect.DeepEqual(actual, expected) {
			return errors.Join(errComponentRuntimeUnconfirmed, err)
		}
		return nil
	}
	if err := verify(); err != nil {
		return true, err
	}
	var err error
	if ownerComponent == "nfqws2" {
		err = a.observeManagedNFQComponent(c, expected)
	} else if ownerComponent == "wireguard" || ownerComponent == "amneziawg" {
		err = a.observeManagedWGComponent(c, expected)
	} else {
		err = a.observeManagedXrayComponent(c, expected)
	}
	if err != nil {
		return true, err
	}
	return true, verify()
}

func (a *App) observeManagedNFQComponent(ctx context.Context, expected dataplane.Plan) error {
	a.managedNFQListMu.Lock()
	r := a.managedNFQList
	a.managedNFQListMu.Unlock()
	if r == nil || !r.original() || r.app != a || r.manager != a.Dataplane || r.policy == nil || r.policy != a.managedListPolicy || !r.policy.original() {
		return dataplane.ErrNFQWSScopedOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.active
	if r.closed || r.pending != nil || e == nil || e.self != e || e.runtime != r || !sameManagedXrayAppliedPlan(expected, e.plan) {
		return dataplane.ErrNFQWSScopedOwner
	}
	cleanup, err := r.control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return err
	}
	c, end, err := r.operation(ctx, e, cleanup)
	if err != nil {
		return err
	}
	defer end()
	return r.manager.CheckRetainedManagedNFQWS(c)
}

func (a *App) observeManagedXrayComponent(ctx context.Context, expected dataplane.Plan) error {
	a.managedXraySelectedTCPListMu.Lock()
	r := a.managedXraySelectedTCPList
	a.managedXraySelectedTCPListMu.Unlock()
	if r == nil || !r.original() || r.app != a || r.manager != a.Dataplane || r.policy != a.managedListPolicy || !r.policy.original() {
		return ErrXrayListSource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.active
	if r.closed || r.pending != nil || r.preparing != nil || e == nil || e.self != e || e.runtime != r || !sameManagedXrayAppliedPlan(expected, e.plan) {
		return ErrXrayListSource
	}
	cleanup, err := r.policy.control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return err
	}
	c, end, err := r.operation(ctx, e, cleanup)
	if err != nil {
		return err
	}
	defer end()
	return r.manager.CheckRetainedManagedXraySelectedTCP(c)
}

// Detector installation facts remain independent. A managed lane's runtime
// label, however, comes only from the actual retained owner observed now.
func (a *App) mergeManagedComponentRuntimeObservation(ctx context.Context, views []components.View) {
	if a == nil || a.Dataplane == nil {
		return
	}
	plan, found, readErr := a.Dataplane.Committed()
	component := managedComponentForPlan(plan)
	for i := range views {
		view := &views[i]
		if view.ID != "nfqws2" && view.ID != "xray" && view.ID != "wireguard" && view.ID != "amneziawg" {
			continue
		}
		if view.ID != component && readErr == nil && !a.hasManagedComponentExecution(view.ID) {
			continue
		}
		view.RuntimeObservation = "unknown"
		view.Running = false
		view.RuntimeVersion = "" // Detector version output is not a live process version.
		view.CanInstall, view.CanUpdate, view.CanRemove = false, false, false
		view.LifecycleBlockReason = "Состояние применённого обхода не подтверждено. Проверьте журнал и область маршрута."
		if readErr == nil && found && view.ID == component {
			if handled, err := a.observeManagedComponentRuntime(ctx, plan, view.ID); handled && err == nil {
				view.RuntimeObservation = "owned"
				view.Running = true
				view.Configured = true
				view.LifecycleBlockReason = "Обход сейчас запущен. Сначала переключите его сервисы и примените изменения."
			}
		}
	}
}

// An App slot with unfinished work selects the closed observation path even
// when its named committed record is lost or replaced. This is not authority.
func (a *App) hasManagedComponentExecution(component string) bool {
	if component == "wireguard" || component == "amneziawg" {
		a.managedWGListMu.Lock()
		r := a.managedWGList
		a.managedWGListMu.Unlock()
		if r == nil {
			return false
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, e := range []*managedWGListExecution{r.preparing, r.active, r.pending} {
			if e == nil {
				continue
			}
			if e.source == nil || e.source.resolved == component {
				return true
			}
		}
		return false
	}
	if component == "nfqws2" {
		a.managedNFQListMu.Lock()
		r := a.managedNFQList
		a.managedNFQListMu.Unlock()
		if r == nil {
			return false
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.active != nil || r.pending != nil
	}
	a.managedXraySelectedTCPListMu.Lock()
	r := a.managedXraySelectedTCPList
	a.managedXraySelectedTCPListMu.Unlock()
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active != nil || r.pending != nil || r.preparing != nil
}
