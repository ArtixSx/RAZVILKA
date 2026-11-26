package nativeowner

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/usquediag/nativeaccept"
)

// COREBinding is frozen by the original coordinator/App review. Review must be
// its trusted current immutable selection/Store guard, never HTTP/client input.
// None of these comparison fields or callback presence issues a capability.
type COREBinding struct {
	Request                    nativeaccept.Request
	Helper                     HelperAsset
	ControlRoot, TransactionID string
	Review                     func(context.Context) error
}

// NewCOREFactory adapts the concrete accepted CORE primitives. It MUST receive
// the actual original same-Gate ExclusiveContext, acquired by coordinator/App.
// It does not Enter/Exclusive, initialize control, or accept a snapshot/receipt.
// Main/sharedApp still owns admission and trusted review wiring. The caller
// releases its original Gate only AFTER known owner settlement; an unknown
// outcome keeps this factory's borrowed lifetime and fence retained.
func NewCOREFactory(ctx context.Context, gate *operationgate.Gate, b COREBinding) (OriginalFactory, error) {
	if ctx == nil || gate == nil || b.Review == nil || nativeaccept.ValidateOwnerRequest(b.Request) != nil || !assetShape(b.Helper) || !pathShape(b.ControlRoot) || !hexShape(b.TransactionID, 32) {
		return nil, ErrOwned
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrOwned
	}
	if gate.WithExclusiveContext(ctx, func() error { return b.Review(ctx) }) != nil {
		return nil, ErrOwned
	}
	epoch, err := gate.ReviewControlEpoch(ctx, b.ControlRoot)
	if err != nil {
		return nil, ErrOwned
	}
	cleanup, err := gate.ReviewExclusiveCleanup(ctx)
	if err != nil {
		_ = epoch.Close()
		return nil, ErrOwned
	}
	f := &coreFactory{gate: gate, original: ctx, binding: b, epoch: epoch, cleanup: cleanup}
	if f.forward(ctx) != nil {
		_ = epoch.Close()
		return nil, ErrOwned
	}
	return f, nil
}

type coreFactory struct {
	mu       sync.Mutex
	gate     *operationgate.Gate
	original context.Context
	binding  COREBinding
	epoch    *operationgate.ControlEpochReview
	cleanup  *operationgate.ExclusiveCleanupReview
	used     bool
	borrowed bool
}

func (f *coreFactory) fresh(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, ErrOwned
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) {
		return nil, nil, ErrOwned
	}
	fresh, cancel := context.WithDeadline(f.original, deadline)
	stop := context.AfterFunc(ctx, cancel)
	return fresh, func() { stop(); cancel() }, nil
}
func (f *coreFactory) forward(ctx context.Context) error {
	fresh, cancel, err := f.fresh(ctx)
	if err != nil {
		return ErrOwned
	}
	defer cancel()
	return f.gate.WithExclusiveContext(fresh, func() error {
		if f.binding.Review(fresh) != nil || f.epoch.Current(fresh) != nil || f.binding.Review(fresh) != nil || f.epoch.Current(fresh) != nil {
			return ErrOwned
		}
		return fresh.Err()
	})
}
func (f *coreFactory) Acquire(ctx context.Context, scope Scope) (OriginalLease, error) {
	f.mu.Lock()
	if f.used {
		f.mu.Unlock()
		return nil, ErrOwned
	}
	f.used = true
	f.mu.Unlock()
	originalDeadline, _ := f.original.Deadline()
	if scope.Acquisition.Request != f.binding.Request || scope.Helper != f.binding.Helper || scope.Deadline.After(originalDeadline) || f.forward(ctx) != nil {
		_ = f.epoch.Close() // no private borrowed lifetime or effect was acquired
		return nil, ErrOwned
	}
	l := &coreLease{factory: f, scope: scope, releaseBorrow: make(chan struct{}), borrowDone: make(chan error, 1)}
	f.mu.Lock()
	f.borrowed = true
	f.mu.Unlock()
	entered := make(chan error, 1)
	// Retain the ALREADY ISSUED private lifetime. This holds no Gate/control
	// mutex. Original release joins it; unknown cleanup cannot release admission.
	go func() {
		called := false
		err := f.gate.WithExclusiveContext(f.original, func() error { called = true; entered <- nil; <-l.releaseBorrow; return nil })
		if !called {
			entered <- err
		}
		l.borrowDone <- err
	}()
	select {
	case err := <-entered:
		if err != nil {
			<-l.borrowDone // callback was never entered; no retained work exists
			f.mu.Lock()
			f.borrowed = false
			f.mu.Unlock()
			_ = f.epoch.Close()
			return nil, ErrOwned
		}
	case <-ctx.Done():
		return l, ErrOwned
	}
	if l.Current(ctx) != nil {
		return l, ErrOwned
	}
	return l, nil
}

// RunCORECoordinator takes an already-issued actual CORE context and frozen
// trusted binding. It is the complete callable native entry for Root/main.
// Existing control must already exist; this function creates no admission or
// registration. The original caller releases its Gate after known settlement.
func RunCORECoordinator(ctx context.Context, gate *operationgate.Gate, b COREBinding) nativeaccept.Result {
	original, err := NewCOREFactory(ctx, gate, b)
	if err != nil {
		return nativeaccept.Result{Status: "blocked", Code: "core-original-review-required", Settlement: "not-acquired", SecretCleanup: "not-staged"}
	}
	f := original.(*coreFactory)
	defer func() {
		f.mu.Lock()
		unused := !f.borrowed
		f.mu.Unlock()
		if unused {
			_ = f.epoch.Close()
		}
	}()
	return RunCoordinator(ctx, b.Request, b.Helper, original)
}

type coreLease struct {
	retained                                   *execution
	mu                                         sync.Mutex
	factory                                    *coreFactory
	scope                                      Scope
	launch                                     nativeaccept.Launch
	launchUsed, starting, helperUsed, released bool
	releaseOnce                                sync.Once
	releaseBorrow                              chan struct{}
	borrowDone                                 chan error
}

// The borrowed original-use goroutine retains this lease. Keep its actual owner
// object/descriptors alive on an unknown runner result; a discarded Result must
// never let GC abandon the private channel/assets while the Gate remains fenced.
func (l *coreLease) retainExecution(e *execution) {
	l.mu.Lock()
	l.retained = e
	l.mu.Unlock()
}

func (l *coreLease) Current(ctx context.Context) error {
	l.mu.Lock()
	released := l.released
	l.mu.Unlock()
	if released {
		return ErrOwned
	}
	return l.factory.forward(ctx)
}
func (l *coreLease) Control(ctx context.Context) (Control, error) {
	if l.Current(ctx) != nil {
		return Control{}, ErrOwned
	}
	ref := l.factory.epoch.Reference()
	return Control{Root: l.factory.binding.ControlRoot, TransactionID: l.factory.binding.TransactionID, InstallationID: ref.InstallationID, Sequence: ref.Sequence}, nil
}
func (l *coreLease) WithStart(ctx context.Context, launch nativeaccept.Launch, begin func() error) error {
	if begin == nil || !launchMatches(l.scope, launch) {
		return ErrOwned
	}
	launch = cloneLaunch(launch)
	l.mu.Lock()
	if l.launchUsed || l.released {
		l.mu.Unlock()
		return ErrOwned
	}
	l.launchUsed = true
	l.launch = launch
	l.starting = true
	l.mu.Unlock()
	defer func() { l.mu.Lock(); l.starting = false; l.mu.Unlock() }()
	fresh, cancel, err := l.factory.fresh(ctx)
	if err != nil {
		return ErrOwned
	}
	defer cancel()
	return l.factory.gate.WithExclusiveContext(fresh, func() error {
		if l.Current(fresh) != nil {
			return ErrOwned
		}
		err := begin()
		return errors.Join(err, l.Current(fresh))
	})
}
func (l *coreLease) WithEffectStart(ctx context.Context, effect string, begin func() error) error {
	l.mu.Lock()
	allowed := l.starting && !l.helperUsed && !l.released && effect == "usque-native-helper"
	if allowed {
		l.helperUsed = true
	}
	l.mu.Unlock()
	if !allowed || begin == nil || l.Current(ctx) != nil {
		return ErrOwned
	}
	fresh, cancel, err := l.factory.fresh(ctx)
	if err != nil {
		return ErrOwned
	}
	defer cancel()
	return l.factory.epoch.WithStart(fresh, begin) // only actual helper Cmd.Start
}
func (l *coreLease) WithCleanup(ctx context.Context, use func() error) error {
	l.mu.Lock()
	released := l.released
	l.mu.Unlock()
	if released || use == nil {
		return ErrOwned
	}
	return l.factory.cleanup.WithCurrent(ctx, use)
}
func (l *coreLease) FenceUnsettled() { l.factory.gate.Fence() }
func (l *coreLease) Release(ctx context.Context) error {
	if l.WithCleanup(ctx, func() error { return l.factory.epoch.Close() }) != nil {
		return ErrOwned
	}
	l.releaseOnce.Do(func() { close(l.releaseBorrow) })
	select {
	case <-ctx.Done():
		l.FenceUnsettled()
		return ErrOwned
	case <-l.borrowDone:
	}
	// Expired/fenced forward checks at borrowed-use return are expected; known
	// cleanup supplied by the concrete owner is not a renewed forward grant.
	l.mu.Lock()
	l.released = true
	l.mu.Unlock()
	return nil
}
