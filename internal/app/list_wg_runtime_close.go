package app

import (
	"context"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func managedWGSelected(route string) bool {
	return route == "wireguard" || strings.HasPrefix(route, "wireguard:") || route == "amneziawg"
}

func (r *ManagedWGListRuntime) Stop(ctx context.Context) error {
	if !r.original() || ctx == nil || ctx.Err() != nil {
		return dataplane.ErrWGOperationOwner
	}
	if _, finite := ctx.Deadline(); !finite {
		return dataplane.ErrWGOperationOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending != nil {
		if r.pending.pendingStop && r.pending.stopBefore != nil {
			return r.stopServiceRuntimeLocked(ctx, r.pending)
		}
		return r.joinPending(ctx)
	}
	e := r.active
	if e == nil {
		e = r.stopped
	}
	if e == nil || e.self != e {
		return dataplane.ErrWGOperationOwner
	}
	c, release, err := r.app.privateExclusiveOperation(componentStopContext(ctx, "stop"))
	if err != nil {
		return err
	}
	owned := true
	defer func() {
		if owned {
			release()
		}
	}()
	cleanup, err := r.app.Operations.ReviewExclusiveCleanup(c)
	if err != nil {
		return err
	}
	if err := r.policy.control.CurrentForCleanupOperation(c, cleanup); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	c, cancel := context.WithDeadline(context.WithoutCancel(c), deadline)
	defer cancel()
	c, end, err := r.operation(c, e, cleanup)
	if err != nil {
		return err
	}
	defer func() {
		if owned {
			end()
		}
	}()
	if e.terminal != nil {
		return e.terminal.ObserveRetired(c, cleanup)
	}
	terminal, err := r.manager.StopRetainedManagedWG(c, cleanup)
	if err == nil {
		e.terminal = terminal
		r.stopped, r.active = e, nil
		return nil
	}
	e.pendingContext, e.pendingCloseOperation, e.pendingRelease = c, end, release
	e.pendingStop = true
	r.pending = e
	owned = false
	r.app.Operations.FenceJournal()
	return err
}

// Retain the original App operation and cleanup capability until the SAME
// Manager rollback or native Stop has joined. The caller supplies only a
// shorter finite retry deadline; it cannot revive any forward operation.
func (r *ManagedWGListRuntime) joinPending(ctx context.Context) error {
	e := r.pending
	if ctx == nil || ctx.Err() != nil || e == nil || e.self != e || e.runtime != r || e.pendingContext == nil || e.pendingCloseOperation == nil || e.pendingRelease == nil {
		return dataplane.ErrWGOperationOwner
	}
	deadline, finite := ctx.Deadline()
	if !finite {
		return dataplane.ErrWGOperationOwner
	}
	if cap := time.Now().Add(15 * time.Second); cap.Before(deadline) {
		deadline = cap
	}
	c, cancel := context.WithDeadline(context.WithoutCancel(e.pendingContext), deadline)
	defer cancel()
	_, op, err := r.executionFor(c)
	if err != nil {
		return err
	}
	if e.pendingStop {
		e.terminal, err = r.manager.StopRetainedManagedWG(c, op.cleanup)
	} else {
		err = r.manager.JoinPendingManagedWG(c, op.cleanup)
	}
	if err != nil {
		return err
	}
	e.pendingCloseOperation()
	e.pendingRelease()
	e.pendingContext, e.pendingCloseOperation, e.pendingRelease = nil, nil, nil
	r.pending, r.active, r.stopped = nil, nil, e
	return nil
}

func (r *ManagedWGListRuntime) Close(ctx context.Context) error {
	if r == nil || r.self != r || r.app == nil || r.app.managedWGList != r {
		return dataplane.ErrWGOperationOwner
	}
	r.mu.Lock()
	closed, live := r.closed, r.active != nil || r.pending != nil
	r.mu.Unlock()
	if closed {
		return r.policy.releaseWG(r)
	}
	if live {
		if err := r.Stop(ctx); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != nil || r.pending != nil || r.preparing != nil {
		return dataplane.ErrWGOperationOwner
	}
	if r.stopped != nil {
		if err := r.stopped.close(); err != nil {
			return err
		}
		r.stopped = nil
	}
	r.closed = true
	return r.policy.releaseWG(r)
}

func (p *managedListPolicyOwner) releaseWG(r *ManagedWGListRuntime) error {
	if p == nil || p.self != p || p.app == nil || p.app.managedListPolicy != p {
		return dataplane.ErrWGOperationOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.wg != r || r == nil || r.self != r || r.policy != p || p.app.managedWGList != r || !r.closed || r.preparing != nil || r.active != nil || r.pending != nil || r.stopped != nil {
		return dataplane.ErrWGOperationOwner
	}
	p.wgClosed = true
	return p.closeIfReleased()
}
