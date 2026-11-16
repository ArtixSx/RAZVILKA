package dataplane

import (
	"context"
	"errors"
	"sync"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type wgInactivityToolObserver interface {
	WithWGInactivityToolObservation(context.Context, netidentity.Identity, string, func(context.Context) error) error
}

// Only the fixed link/table kernel-read bodies use this loan, after deriving
// their context from the retained session. CLI/effects and arbitrary consumers
// never enter it. Every original CheckWG, process/root and kernel read remains.
func (r *WGInactivityRead) observeKernelTools(ctx context.Context, s *wgInactivityReadSession, use func(context.Context) error) error {
	if r == nil || r.self != r || s == nil || s.self != s || s.source != r || use == nil || !wgInactivityFinite(ctx) || ctx.Value(wgInactivitySessionKey{}) != s {
		return ErrWGOperationOwner
	}
	observer, ok := r.tools.Runner.(wgInactivityToolObserver)
	if !ok || s.cleanup != nil {
		return use(ctx)
	}
	tools := r.tools
	deadline, _ := ctx.Deadline()
	same := func(c context.Context) error {
		if !wgInactivityFinite(c) || ctx.Err() != nil || c.Value(wgInactivitySessionKey{}) != s {
			return ErrWGOperationOwner
		}
		end, _ := c.Deadline()
		if end.After(deadline) || s.source != r || r.self != r || !sameNetworkPolicyDependency(tools.Runner, r.tools.Runner) || tools.Provider != r.tools.Provider || tools.Identity != r.tools.Identity || tools.ReviewSHA256 != r.tools.ReviewSHA256 || tools.EngineID != r.tools.EngineID || tools.IP != r.tools.IP || tools.IPTables != r.tools.IPTables || tools.IP6Tables != r.tools.IP6Tables || tools.WG != r.tools.WG || tools.AWG != r.tools.AWG {
			return ErrWGOperationOwner
		}
		s.mu.Lock()
		open := s.open && s.ctx != nil && s.ctx.Err() == nil
		s.mu.Unlock()
		if !open {
			return ErrWGOperationOwner
		}
		return r.pureCurrent(c)
	}
	if err := same(ctx); err != nil {
		return err
	}
	result := wgKernelToolComparison(ctx, func(c context.Context, read func(context.Context) error) error {
		return observer.WithWGInactivityToolObservation(c, tools.Identity, tools.ReviewSHA256, read)
	}, same, use)
	return errors.Join(result, same(ctx))
}

// Same single-entry, seal/cancel/join protocol as other original tool loans.
// No mutex spans a source callback. An observer cannot hide a body failure or
// recover its panic and manufacture successful completed observation.
func wgKernelToolComparison(ctx context.Context, observe func(context.Context, func(context.Context) error) error, same func(context.Context) error, read func(context.Context) error) (result error) {
	var mu sync.Mutex
	open, entered, complete, misuse := true, false, false, false
	var revoke context.CancelFunc
	var bodyErr error
	done := make(chan struct{})
	defer func() {
		mu.Lock()
		open = false
		didEnter, cancel := entered, revoke
		mu.Unlock()
		if didEnter {
			select {
			case <-done:
			default:
				mu.Lock()
				misuse = true
				mu.Unlock()
				cancel()
				<-done
			}
		}
		mu.Lock()
		defer mu.Unlock()
		result = errors.Join(result, bodyErr, ctx.Err())
		if !didEnter || !complete || misuse {
			result = errors.Join(result, ErrWGOperationOwner)
		}
	}()
	return observe(ctx, func(ownerCtx context.Context) error {
		mu.Lock()
		if !open || entered || ownerCtx == nil {
			misuse = true
			mu.Unlock()
			return ErrWGOperationOwner
		}
		entered = true
		observed, cancel := context.WithCancel(ownerCtx)
		revoke = cancel
		mu.Unlock()
		defer close(done)
		defer cancel()
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
		if ctx.Err() != nil {
			cancel()
		}
		err := same(observed)
		if err == nil {
			err = errors.Join(read(observed), same(observed))
		}
		mu.Lock()
		bodyErr, complete = err, true
		mu.Unlock()
		return err
	})
}
