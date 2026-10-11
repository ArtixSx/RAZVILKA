package app

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func managedWGPlan(plan dataplane.Plan) bool {
	if plan.LAN == nil || plan.LAN.Mode != "" || len(plan.Routes) == 0 {
		return false
	}
	engine := ""
	for _, route := range plan.Routes {
		if !managedWGSelected(route.Resolved) {
			return false
		}
		id := dataplane.AdapterID(route.Resolved)
		if engine != "" && engine != id {
			return false
		}
		engine = id
	}
	return engine == "wireguard" || engine == "amneziawg"
}

func (a *App) observeCommittedManagedWG(ctx context.Context, expected dataplane.Plan) (bool, error) {
	if !managedWGPlan(expected) {
		return false, nil
	}
	if a == nil || expected.State != "committed" {
		return true, dataplane.ErrWGOperationOwner
	}
	a.managedWGListMu.Lock()
	r := a.managedWGList
	a.managedWGListMu.Unlock()
	if r == nil || !r.original() {
		return true, dataplane.ErrWGOperationOwner
	}
	c, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.active
	if e == nil || r.pending != nil || !sameManagedWireGuardAppliedPlan(expected, e.plan) {
		return true, dataplane.ErrWGOperationOwner
	}
	verify := func() error {
		actual, found, err := r.manager.Committed()
		if err != nil || !found || !reflect.DeepEqual(actual, expected) {
			return errors.Join(dataplane.ErrWGOperationOwner, err)
		}
		return nil
	}
	if err := verify(); err != nil {
		return true, err
	}
	if err := r.currentLocked(c); err != nil {
		return true, err
	}
	return true, verify()
}

func (a *App) observeManagedWGComponent(ctx context.Context, expected dataplane.Plan) error {
	a.managedWGListMu.Lock()
	r := a.managedWGList
	a.managedWGListMu.Unlock()
	if r == nil || !r.original() || r.policy != a.managedListPolicy || !managedWGPlan(expected) {
		return dataplane.ErrWGOperationOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.active
	if e == nil || r.pending != nil || r.preparing != nil || !sameManagedWireGuardAppliedPlan(expected, e.plan) {
		return dataplane.ErrWGOperationOwner
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
	return r.manager.CheckRetainedManagedWG(c)
}

func (a *App) executeManagedServiceRuntime(ctx context.Context, action string, revision uint64) (bool, serviceRuntimeOutcome) {
	if handled, outcome := a.executeManagedWGServiceRuntime(ctx, action, revision); handled {
		return true, outcome
	}
	return a.executeManagedXrayServiceRuntime(ctx, action, revision)
}
