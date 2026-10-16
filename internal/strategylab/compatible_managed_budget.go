package strategylab

import (
	"context"
	"time"
)

// These context constructors are kept separate from receipt/owner checks.
// A deadline is a bound on work, never evidence that the work succeeded.
func compatibilityValidatorContext(parent context.Context, v CompatibleValidator) (context.Context, context.CancelFunc) {
	timeout := v.Timeout
	if timeout <= 0 || timeout > ProbeTimeout {
		timeout = 8 * time.Second
	}
	return context.WithTimeout(parent, timeout)
}

func compatibilityPhaseContext(parent context.Context, p *SupervisedCompatibilityProvider) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, ProbeTimeout)
}

func compatibilityPublicationContext(parent context.Context, active *compatibilityInvocation) (context.Context, context.CancelFunc) {
	return context.WithDeadline(parent, active.Command.Deadline)
}

func compatibilityPublicationTimeCurrent(ctx context.Context, active *compatibilityInvocation) bool {
	return time.Now().Before(active.Command.Deadline)
}
