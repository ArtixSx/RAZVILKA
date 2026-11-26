package app

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"reflect"
	"time"
)

// Ordinary readers enter through the concrete SAME-App operation. A decoded
// selected plan merely chooses this closed dispatch and cannot issue its owner.
func (a *App) observeCommittedManagedXray(ctx context.Context, expected dataplane.Plan) (bool, error) {
	if expected.LAN == nil || expected.LAN.Mode != dataplane.LANPolicyXraySelectedTCPMode {
		return false, nil
	}
	if a == nil || expected.State != "committed" {
		return true, ErrXrayListSource
	}
	a.managedXraySelectedTCPListMu.Lock()
	r := a.managedXraySelectedTCPList
	a.managedXraySelectedTCPListMu.Unlock()
	if r == nil || !r.original() {
		return true, ErrXrayListSource
	}
	c, end := context.WithTimeout(ctx, 8*time.Second)
	defer end()
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.active
	if e == nil || r.pending != nil || expected.PlanID != e.plan.PlanID || expected.Digest != e.plan.Digest || expected.Revision != e.plan.Revision ||
		expected.NetworkProfileID != e.plan.NetworkProfileID || !reflect.DeepEqual(expected.LAN, e.plan.LAN) || !reflect.DeepEqual(expected.Routes, e.plan.Routes) {
		return true, ErrXrayListSource
	}
	verify := func() error {
		actual, found, err := r.manager.Committed()
		if err != nil || !found || !reflect.DeepEqual(actual, expected) {
			return errors.Join(ErrXrayListSource, err)
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
