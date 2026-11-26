package dataplane

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Only the SAME existing runner can lend its immutable bytes. No consumer,
// WG preflight, authority callback or effect is enclosed. Every actual kernel
// read, image comparison, tool callback and namespace bookend remains fresh.
type backendInventoryReadObserver interface {
	WithReadOnlyToolObservation(context.Context, netidentity.Identity, string, func(context.Context) error) error
}

func (r *backendInventoryReader) captureWithToolObservation(ctx context.Context, scope backendInventoryScope, platform backendInventoryPlatform, runner backendInventoryBoundedRunner) (backendInventorySnapshot, error) {
	original, supported := runner.(backendInventoryReadObserver)
	if !supported {
		return r.capture(ctx, scope, platform, runner)
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !time.Now().Before(deadline) {
		return backendInventorySnapshot{}, errors.Join(errBackendInventory, ctx.Err())
	}
	request, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	open, entered, misuse := true, false, false
	var snapshot backendInventorySnapshot
	var callbackErr error
	done := make(chan struct{})
	// Revoke late use and join an already entered reader before returning to
	// the Provider's closing observation, including error and panic paths.
	closeObservation := func() bool {
		mu.Lock()
		open = false
		didEnter := entered
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
		return didEnter
	}
	defer closeObservation()
	ownerErr := original.WithReadOnlyToolObservation(request, scope.Network, scope.ToolReviewID, func(observed context.Context) error {
		mu.Lock()
		if !open || entered || observed == nil {
			misuse = true
			mu.Unlock()
			return errBackendInventory
		}
		entered = true
		mu.Unlock()
		defer close(done)
		observedDeadline, finite := observed.Deadline()
		if !finite || observedDeadline.After(deadline) {
			callbackErr = errBackendInventory
			return callbackErr
		}
		read, revoke := context.WithDeadline(observed, deadline)
		defer revoke()
		stop := context.AfterFunc(request, revoke)
		defer stop()
		if request.Err() != nil {
			revoke()
		}
		snapshot, callbackErr = r.capture(read, scope, platform, runner)
		callbackErr = errors.Join(callbackErr, read.Err(), request.Err())
		return callbackErr
	})
	didEnter := closeObservation()
	mu.Lock()
	bad := misuse
	mu.Unlock()
	if !didEnter || bad || ownerErr != nil || callbackErr != nil || ctx.Err() != nil {
		failure := errors.Join(errBackendInventory, ownerErr, callbackErr, ctx.Err())
		var staged *backendInventoryFailure
		if errors.As(failure, &staged) {
			return backendInventorySnapshot{}, failure // Preserve the actual original capture stage.
		}
		return backendInventorySnapshot{}, backendInventoryAt("TOOL_OBSERVATION", failure)
	}
	return snapshot, nil
}
