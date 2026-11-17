package app

import (
	"context"
	"errors"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Only startReviewed creates this frame while holding r.mu and the original
// exclusive lease. Neither a request context nor a receipt can create it.
type managedNFQPendingFrame struct {
	self                          *managedNFQPendingFrame
	execution                     *managedNFQWSListExecution
	original                      context.Context
	closeOperation, release, take func()
	used                          bool
}

func (f *managedNFQPendingFrame) retain(ctx context.Context, app *App, plan dataplane.Plan) bool {
	if f == nil || f.self != f || f.used || f.execution == nil || f.original != ctx || f.closeOperation == nil || f.release == nil || f.take == nil {
		return false
	}
	f.used = true
	e := f.execution
	r := e.runtime
	if r == nil || !r.original() || r.app != app || r.pending != nil || r.active != nil || r.panel.Err() != nil || !reflect.DeepEqual(plan, e.plan) {
		return false
	}
	// A canceled forward request does not cancel its already-held original
	// cleanup admission. This is a fresh finite review, never a new Apply.
	c, cancel := context.WithTimeout(context.WithoutCancel(ctx), managedNFQCleanupBudget)
	defer cancel()
	original, op, err := r.executionFor(c)
	if err != nil || original != e {
		return false
	}
	err = op.cleanup.WithCurrent(c, func() error {
		if err := e.quarantineStoreCurrent(c); err != nil {
			return err
		}
		q, err := r.manager.ReviewPendingNFQWSQuarantine(c)
		if err != nil {
			return err
		}
		// Transfer all originals before leaving the callback: closing failure may
		// promote a permanent fence, but cannot release the pending cleanup owner.
		e.pendingQuarantine = q
		e.pendingContext, e.pendingCloseOperation, e.pendingRelease = ctx, f.closeOperation, f.release
		r.pending = e
		f.take()
		e.pendingShutdownDone = make(chan struct{})
		shutdownDone := e.pendingShutdownDone
		e.pendingShutdownStop = context.AfterFunc(r.panel, func() { defer close(shutdownDone); q.Revoke(); app.Operations.FenceJournal() })
		return e.quarantineStoreCurrent(c)
	})
	if err != nil || r.panel.Err() != nil || app.Operations.Snapshot().Fenced {
		if e.pendingQuarantine != nil {
			e.pendingQuarantine.Revoke()
		}
		return false
	}
	return e.pendingQuarantine != nil
}

func (e *managedNFQWSListExecution) quarantineStoreCurrent(ctx context.Context) error {
	e.mu.RLock()
	expected, catalog := e.expected, e.catalog
	e.mu.RUnlock()
	if applyReviewHash(e.runtime.app.catalogSnapshot()) != catalog {
		return dataplane.ErrReviewChanged
	}
	return (&DefaultRouteExecutor{app: e.runtime.app}).observeConfig(ctx, expected)
}

// r.mu and the SAME original exclusive cleanup lease remain held throughout.
// A prior permanent fence is never cleared, even after a later successful join.
func (r *ManagedNFQWSListRuntime) finishPendingQuarantine(ctx context.Context, e *managedNFQWSListExecution, op *managedNFQWSListOperation) error {
	q := e.pendingQuarantine
	if q == nil || !e.pendingJoined || e != r.pending || op == nil || op.execution != e || op.cleanup == nil {
		return dataplane.ErrNFQWSScopedOwner
	}
	fail := func(err error) error { q.Revoke(); r.app.Operations.FenceJournal(); return err }
	verify := func() error {
		if r.app.Operations.Snapshot().Fenced {
			return q.VerifyJoinedCleanup(ctx)
		}
		return q.Joined(ctx)
	}
	err := op.cleanup.WithCurrent(ctx, func() error {
		if r.panel.Err() != nil {
			return r.panel.Err()
		}
		if err := verify(); err != nil {
			return err
		}
		if err := e.quarantineStoreCurrent(ctx); err != nil {
			return err
		}
		if !e.pendingSourcesClosing {
			if err := r.control.CurrentForCleanup(ctx); err != nil {
				return err
			}
			if err := e.source.Current(ctx); err != nil {
				return err
			}
			if err := e.component.Check(ctx); err != nil {
				return err
			}
			if err := e.scopeCleanupCurrent(ctx, e.plan.LAN); err != nil {
				return err
			}
			e.pendingSourcesClosing = true
		}
		if err := e.closeQuarantineSources(); err != nil {
			return err
		}
		if err := managedNFQQuarantineClosingFault(q); err != nil {
			return err
		}
		// Publication FDs outlive source closure. No named file is reopened to
		// reconstruct a completion witness after originals were destroyed.
		return errors.Join(verify(), e.quarantineStoreCurrent(ctx), r.panel.Err())
	})
	if err != nil {
		return fail(err)
	}
	if err := q.Close(); err != nil {
		return fail(err)
	}
	if e.pendingShutdownStop != nil {
		if !e.pendingShutdownStop() {
			<-e.pendingShutdownDone
		}
		e.pendingShutdownStop, e.pendingShutdownDone = nil, nil
	}
	// Source shutdown racing unregister must still fence before lease release.
	if r.panel.Err() != nil {
		return fail(r.panel.Err())
	}
	e.pendingCloseOperation()
	e.pendingRelease()
	e.pendingRelease, e.pendingCloseOperation, e.pendingContext = nil, nil, nil
	e.pendingQuarantine = nil
	r.pending = nil
	return nil
}

// A partial close cannot become positive terminal knowledge. Individual source
// owners retain their own close-once result; a retry does not mint replacements.
func (e *managedNFQWSListExecution) closeQuarantineSources() error {
	e.pendingSourcesClosing = true
	if e.pendingSourcesClosed {
		return nil
	}
	if err := e.close(); err != nil {
		return err
	}
	e.pendingSourcesClosed = true
	return nil
}
