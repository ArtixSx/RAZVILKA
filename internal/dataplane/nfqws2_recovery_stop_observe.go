package dataplane

import (
	"context"
	"reflect"
)

// ObserveNFQWS2RecoveryStopInactive is a read-only owner observation. It may
// run inside an existing Manager Apply; it neither enters a second operation
// gate nor grants execution/journal admission. The original committed plan
// remains immutable until publication of the reviewed empty Stop transaction.
func (m *Manager) ObserveNFQWS2RecoveryStopInactive(ctx context.Context, expected Plan) error {
	if ctx == nil {
		return ErrRuntimeInactivity
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if m == nil || expected.State != "committed" || expected.SafeMode || expected.Noop || expected.LAN != nil || expected.DNS != nil || len(expected.Adapters) != 1 || expected.Adapters[0] != "nfqws2" || len(expected.Routes) == 0 {
		return ErrRuntimeInactivity
	}
	for _, r := range expected.Routes {
		if r.Resolved != "nfqws2" {
			return ErrRuntimeInactivity
		}
	}
	current, exists, err := m.Committed()
	if err != nil || !exists || !reflect.DeepEqual(current, expected) {
		return ErrReviewChanged
	}
	m.registryMu.RLock()
	a := m.Adapters["nfqws2"]
	generation := m.registryGeneration
	m.registryMu.RUnlock()
	owner, ok := a.(RuntimeInactivityObserver)
	if !ok || owner == nil || isNilRuntimeObserver(owner) {
		return ErrRuntimeInactivity
	}
	if err := owner.VerifyRuntimeInactive(ctx); err != nil {
		return err
	}
	m.registryMu.RLock()
	same := generation == m.registryGeneration && m.Adapters["nfqws2"] == a
	m.registryMu.RUnlock()
	if !same {
		return ErrReviewChanged
	}
	current, exists, err = m.Committed()
	if err != nil || !exists || !reflect.DeepEqual(current, expected) {
		return ErrReviewChanged
	}
	return ctx.Err()
}
