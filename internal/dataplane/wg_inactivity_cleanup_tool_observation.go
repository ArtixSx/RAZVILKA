package dataplane

import (
	"context"
	"errors"
	"sync"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type wgInactivityCleanupToolObserver interface {
	WithWGInactivityCleanupToolObservation(context.Context, netidentity.Identity, string, func(context.Context) error) error
}

// Only the two fixed kernel-read bodies enter this comparison. The original
// session already retains its SAME cleanup operation and joins this read.
// CLI, lifecycle effects and caller-supplied consumer bodies remain outside.
func (r *WGInactivityRead) observeCleanupKernelTools(ctx context.Context, s *wgInactivityReadSession, use func(context.Context) error) error {
	if r == nil || r.self != r || s == nil || s.self != s || s.source != r || use == nil || !wgInactivityFinite(ctx) || ctx.Value(wgInactivitySessionKey{}) != s {
		return ErrWGOperationOwner
	}
	observer, ok := r.tools.Runner.(wgInactivityCleanupToolObserver)
	if !ok || s.cleanup == nil {
		return use(ctx) // Preserve the original non-cleanup/older source path.
	}
	tools, control, cleanup, sessionContext := r.tools, r.control, s.cleanup, s.ctx
	deadline, _ := ctx.Deadline()
	same := func(c context.Context) error {
		if !wgInactivityFinite(c) || ctx.Err() != nil || c.Value(wgInactivitySessionKey{}) != s {
			return ErrWGOperationOwner
		}
		end, _ := c.Deadline()
		if end.After(deadline) || s.self != s || s.source != r || s.cleanup != cleanup || s.ctx != sessionContext || r.self != r || r.control != control || control == nil ||
			!sameNetworkPolicyDependency(tools.Runner, r.tools.Runner) || tools.Provider != r.tools.Provider || tools.Identity != r.tools.Identity || tools.ReviewSHA256 != r.tools.ReviewSHA256 || tools.EngineID != r.tools.EngineID || tools.IP != r.tools.IP || tools.IPTables != r.tools.IPTables || tools.IP6Tables != r.tools.IP6Tables || tools.WG != r.tools.WG || tools.AWG != r.tools.AWG {
			return ErrWGOperationOwner
		}
		s.mu.Lock()
		open := s.open && sessionContext != nil && sessionContext.Err() == nil
		s.mu.Unlock()
		if !open {
			return ErrWGOperationOwner
		}
		return r.pureCurrent(c)
	}
	if err := same(ctx); err != nil {
		return err
	}
	// This is a nested lifetime use, not a new cleanup review or forward grant.
	// No Gate/control mutex spans the tool observer or kernel callbacks.
	if err := control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return err
	}
	result := wgCleanupKernelToolComparison(ctx, func(c context.Context, read func(context.Context) error) error {
		return observer.WithWGInactivityCleanupToolObservation(c, tools.Identity, tools.ReviewSHA256, read)
	}, same, use)
	return errors.Join(result, same(ctx), control.CurrentForCleanupOperation(ctx, cleanup))
}

// Revoke and join entered work on EVERY observer exit, including panic/Goexit.
// The returned kernel data remains provisional until the observer closes its
// byte graph and this function has sealed the single permitted callback.
func wgCleanupKernelToolComparison(ctx context.Context, observe func(context.Context, func(context.Context) error) error, same func(context.Context) error, read func(context.Context) error) (result error) {
	if !wgInactivityFinite(ctx) || observe == nil || same == nil || read == nil {
		return ErrWGOperationOwner
	}
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
