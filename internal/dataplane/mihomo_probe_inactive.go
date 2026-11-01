package dataplane

import (
	"context"
	"errors"
	"time"
)

// VerifyRuntimeInactive implements the same complete registry contract as the
// other adapters. The finite probe owns no persistent network policy or fixed
// socket reservation. Its original busy/pending slots and real process images
// must nevertheless be absent. Manager separately brackets this observation
// with the unchanged execution recovery and registry checks.
func (a *MihomoProbeAdapter) VerifyRuntimeInactive(parent context.Context) error {
	if a == nil || a.self != a || parent == nil || a.components == nil || a.provider == nil {
		return ErrRuntimeInactivity
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	a.mu.Lock()
	if a.busy || a.pending != nil {
		a.mu.Unlock()
		return ErrRuntimeInactivity
	}
	// Reserve the original slot through closing observations. No new probe can
	// start in the interval between the two physical inventories.
	a.busy = true
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.busy = false; a.mu.Unlock() }()
	replacement, err := a.replacementObservation(ctx)
	if err != nil {
		return errors.Join(ErrRuntimeInactivity, err)
	}
	if err := observeMihomoProbeInactive(ctx, a.provider, replacement); err != nil {
		return errors.Join(ErrRuntimeInactivity, err)
	}
	a.mu.Lock()
	unchanged := a.busy && a.pending == nil
	a.mu.Unlock()
	if !unchanged {
		return ErrRuntimeInactivity
	}
	return ctx.Err()
}
