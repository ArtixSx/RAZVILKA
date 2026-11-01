package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type domainTCPToolObserver interface {
	WithReadOnlyToolObservation(context.Context, netidentity.Identity, string, func(context.Context) error) error
}

// Only one synchronous readonly COMMON callback borrows this original source.
// Every mutation/actual Start uses its caller's original context, after this
// scope has revoked and joined its held readers and closed its complete SHA.
func (r *domainTCPCaptureExecutionResource) observeTools(ctx context.Context, use func(context.Context) error) error {
	if use == nil {
		return ErrDomainPolicyTCPConsumer
	}
	if err := r.local(ctx); err != nil {
		return err
	}
	original, ok := r.backend.reader.Runner.(domainTCPToolObserver)
	if !ok {
		return use(ctx)
	} // Existing producers retain their full-check path.
	return original.WithReadOnlyToolObservation(ctx, r.tools.Identity, r.tools.ReviewSHA256, use)
}

func (r *syntheticBaselineExecutionResource) observeTools(ctx context.Context, use func(context.Context) error) error {
	if use == nil {
		return ErrSyntheticBaselineTransition
	}
	if err := r.local(ctx); err != nil {
		return err
	}
	original, ok := r.backend.reader.Runner.(domainTCPToolObserver)
	if !ok {
		return use(ctx)
	}
	return original.WithReadOnlyToolObservation(ctx, r.tools.Identity, r.tools.ReviewSHA256, use)
}

func (r *syntheticBaselineExecutionResource) observeOriginalFiles(ctx context.Context, use func(*xrayDomainTCPFileObservation) error) error {
	if use == nil {
		return ErrSyntheticBaselineTransition
	}
	if r == nil || r.self != r {
		return ErrSyntheticBaselineTransition
	}
	if r.capture == nil || r.capture.xray == nil || r.capture.xray.resource == nil {
		return use(nil)
	}
	process := r.capture.xray.resource
	if process.material == nil || process.material.binding != r.binding {
		return ErrSyntheticBaselineTransition
	}
	return process.withCurrentFileObservation(ctx, use)
}
