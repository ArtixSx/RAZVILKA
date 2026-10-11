package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

type managedListStartupFailure struct {
	stage string
	cause error
}

func (e *managedListStartupFailure) Error() string {
	return fmt.Sprintf("managed list startup refused at %s: %v", e.stage, e.cause)
}
func (e *managedListStartupFailure) Unwrap() error { return e.cause }

// Fixed stage only: no paths, private profile material or arbitrary error text
// is exposed by this diagnostic helper.
func ManagedListStartupFailureStage(err error) string {
	var failure *managedListStartupFailure
	if errors.As(err, &failure) {
		return failure.stage
	}
	return "constructor"
}

// Startup construction never receives a resource/child issuer. Retain its
// concrete attempt and actual tool/check owners even when construction fails;
// nil runtime return values provide no proof of a joined close.
func (p *managedListPolicyOwner) closeStartupResources() error {
	if p == nil || p.self != p || p.app == nil || p.app.managedListPolicy != p || p.app.Dataplane != p.manager || p.manager == nil {
		return dataplane.ErrRuntimeInactivity
	}
	if p.nfq != nil && !p.nfqClosed || p.xray != nil && !p.xrayClosed || p.wg != nil && !p.wgClosed {
		return dataplane.ErrRuntimeInactivity
	}
	if p.closed.Load() {
		return p.closeErr
	}
	err := p.closeWGInactivity()
	if p.checks != nil {
		err = errors.Join(err, p.checks.Close())
	}
	if p.tools != nil {
		err = errors.Join(err, p.tools.Close())
	}
	// Control belongs to the original App. The constructor's existing
	// closeUnretainedManagedNFQControl owns only a newly unretained review.
	p.closeErr = errors.Join(p.closeErr, err)
	if p.closeErr == nil {
		p.closed.Store(true)
	}
	return p.closeErr
}

// Call after the actual returned runtimes have closed. A missing attempt,
// copied/foreign App, open runtime, or unknown native owner always refuses.
// Success confirms only joined startup ownership; native Stop remains owned
// by each existing runtime's Close and its original compensation.
func (a *App) CloseManagedListStartup(ctx context.Context) error {
	if a == nil || ctx == nil || ctx.Err() != nil {
		return dataplane.ErrRuntimeInactivity
	}
	if _, finite := ctx.Deadline(); !finite {
		return dataplane.ErrRuntimeInactivity
	}
	a.managedListPolicyMu.Lock()
	defer a.managedListPolicyMu.Unlock()
	p := a.managedListPolicy
	if p == nil || p.self != p || p.app != a || p.manager == nil || p.manager != a.Dataplane || p.panel == nil {
		return dataplane.ErrRuntimeInactivity
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.startupReady && p.startupFailure == nil {
		return dataplane.ErrRuntimeInactivity
	}
	if p.nfq != a.managedNFQList || p.xray != a.managedXraySelectedTCPList || p.wg != a.managedWGList {
		return dataplane.ErrRuntimeInactivity
	}
	if p.nfq != nil && (!p.nfqClosed || !p.nfq.closed || p.nfq.active != nil || p.nfq.pending != nil) {
		return dataplane.ErrRuntimeInactivity
	}
	if p.xray != nil && (!p.xrayClosed || !p.xray.closed || p.xray.preparing != nil || p.xray.active != nil || p.xray.pending != nil) {
		return dataplane.ErrRuntimeInactivity
	}
	if p.wg != nil && (!p.wgClosed || !p.wg.closed || p.wg.preparing != nil || p.wg.active != nil || p.wg.pending != nil || p.wg.stopped != nil) {
		return dataplane.ErrRuntimeInactivity
	}
	if a.Dataplane.HasPendingManagedNFQWS() || a.Dataplane.HasPendingManagedXraySelectedTCP() || a.Dataplane.HasPendingManagedWG() {
		return dataplane.ErrRuntimeInactivity
	}
	return errors.Join(p.closeStartupResources(), ctx.Err())
}
