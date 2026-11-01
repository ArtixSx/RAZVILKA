package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type nfqwsProbeToolObserver interface {
	WithReadOnlyToolObservation(context.Context, netidentity.Identity, string, func(context.Context) error) error
}

func (e *nfqwsProbeExecution) observeTools(ctx context.Context, use func(context.Context) error) error {
	if e == nil || e.self != e || e.consumer == nil || e.consumer.self != e.consumer || !e.consumer.OwnsContext(ctx) || e.socket == nil || use == nil {
		return ErrNFQWSScopedOwner
	}
	original, ok := e.consumer.inventory.reader.Runner.(nfqwsProbeToolObserver)
	if !ok {
		return use(ctx)
	} // Existing unsupported producers keep full checks.
	return original.WithReadOnlyToolObservation(ctx, e.socket.identity, e.consumer.inventory.review, use)
}

func (b *NFQWSScopedBinding) observeProbeTools(ctx context.Context, p *NFQWSScopedPlan, use func(context.Context) error) error {
	if ctx == nil || use == nil {
		return ErrNFQWSScopedOwner
	}
	if p == nil || p.spec.Probe == nil {
		return use(ctx)
	}
	e, _ := ctx.Value(nfqwsProbeExecutionKey{}).(*nfqwsProbeExecution)
	// Bare models and deliberate readonly binding copies retain their previous
	// full-check path. Only the exact original producer gets the finite loan.
	if e == nil || e.binding != b {
		return use(ctx)
	}
	if e.self != e || e.resource == nil || e.resource.plan != p {
		return ErrNFQWSScopedOwner
	}
	return e.observeTools(ctx, use)
}
