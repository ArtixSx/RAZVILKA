package strategylab

import (
	"context"
	"errors"
	"time"
)

const (
	ManagedCompatibilityAcquisitionTimeout = 5 * time.Second
	managedCompatibilityAdmissionTimeout   = 5 * time.Second
	managedCompatibilityPhaseTimeout       = 8 * time.Second
	managedCompatibilityPublicationTimeout = 5 * time.Second
	managedCompatibilityForwardTimeout     = managedCompatibilityAdmissionTimeout + 2*(managedCompatibilityPhaseTimeout+managedCompatibilityCleanupTimeout) + managedCompatibilityPublicationTimeout
	// Cleanup/sole Wait and completion retirement retain their existing owners
	// after expiry. This is a forward-work deadline, not a forced join timeout.
	ManagedCompatibilityRequestTimeout = ManagedCompatibilityAcquisitionTimeout + managedCompatibilityForwardTimeout
)

// Only the same private invocation retains its original bounded forward ctx.
// Copied DTO/receipt data and a fresh caller context cannot renew this deadline.
func managedCompatibilityForward(ctx context.Context) *managedCompatibilityInvocation {
	if ctx == nil {
		return nil
	}
	i, _ := ctx.Value(managedCompatibilityContextKey{}).(*managedCompatibilityInvocation)
	if i == nil || i.forward == nil || i.forward.Value(managedCompatibilityContextKey{}) != i || !managedCompatibilityRun(ctx, i.provider) {
		return nil
	}
	return i
}

func (i *managedCompatibilityInvocation) forwardCurrent(ctx context.Context) error {
	if i == nil || managedCompatibilityForward(ctx) != i {
		return errAdaptiveManagedValidator
	}
	return errors.Join(selectedReviewContext(i.forward), selectedReviewContext(ctx))
}

// These context constructors are kept separate from receipt/owner checks.
// A deadline is a bound on work, never evidence that the work succeeded.
func compatibilityValidatorContext(parent context.Context, v CompatibleValidator) (context.Context, context.CancelFunc) {
	if p, ok := v.Provider.(*SupervisedCompatibilityProvider); ok && managedCompatibilityForward(parent) != nil && managedCompatibilityRun(parent, p) {
		return context.WithCancel(parent)
	}
	timeout := v.Timeout
	if timeout <= 0 || timeout > ProbeTimeout {
		timeout = 8 * time.Second
	}
	return context.WithTimeout(parent, timeout)
}

func compatibilityPhaseContext(parent context.Context, p *SupervisedCompatibilityProvider) (context.Context, context.CancelFunc) {
	if managedCompatibilityForward(parent) != nil && managedCompatibilityRun(parent, p) {
		return context.WithTimeout(parent, managedCompatibilityPhaseTimeout)
	}
	return context.WithTimeout(parent, ProbeTimeout)
}

func compatibilityPublicationContext(parent context.Context, active *compatibilityInvocation) (context.Context, context.CancelFunc) {
	if managedCompatibilityForward(parent) != nil {
		return context.WithTimeout(parent, managedCompatibilityPublicationTimeout)
	}
	return context.WithDeadline(parent, active.Command.Deadline)
}

func compatibilityPublicationTimeCurrent(ctx context.Context, active *compatibilityInvocation) bool {
	if i := managedCompatibilityForward(ctx); i != nil {
		return i.forwardCurrent(ctx) == nil
	}
	return time.Now().Before(active.Command.Deadline)
}
