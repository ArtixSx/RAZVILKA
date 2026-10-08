package app

import (
	"context"
	"errors"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// cleanupScopeCheck compares only the SAME original retained physics and
// immutable bound LAN plan. The concrete App cleanup owner calls this inside
// its actual pre-issued operation cleanup capability. This read grants no
// command, process ownership or forward scope and never reads Store/selection.
func (b *ListScopeBinding) cleanupScopeCheck(ctx context.Context, plan *dataplane.LANPolicyRuntimePlan) error {
	if b == nil || b.self != b || b.app == nil || ctx == nil {
		return ErrListScopeChanged
	}
	c, cancel, err := listScopeContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.app.Store != b.store || !b.boundOnce || b.bound == nil || b.verifyCleanupPhysical == nil || b.physicalSnapshot == nil || dataplane.ValidateLANPolicyRuntime(plan) != nil || !reflect.DeepEqual(b.bound, plan) || !reflect.DeepEqual(b.facts, b.physicalSnapshot()) {
		return ErrListScopeChanged
	}
	if err := b.verifyCleanupPhysical(c); err != nil {
		return errors.Join(ErrListScopeChanged, err)
	}
	if b.closed || !reflect.DeepEqual(b.facts, b.physicalSnapshot()) {
		return ErrListScopeChanged
	}
	return c.Err()
}
