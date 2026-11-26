package dataplane

import "context"

// A fresh operation reads the original capture only after Manager has retained
// that SAME scope. Neither a new Context nor metadata can extend forward Apply.
func (r *WGSourceReadReview) sourceCurrentPure(ctx context.Context, retained bool) error {
	if !retained {
		return r.pureCurrent(ctx)
	}
	if err := r.metadataCurrent(ctx); err != nil {
		return err
	}
	o, ok := ctx.Value(wgOperationOwnerKey{}).(*wgOperationOwner)
	if !ok || o == nil || o.self != o || o.scope == nil || o.scope.wgOwner != o || o.material == nil || o.material.source == nil ||
		o.material.source.reader != r || o.adapter != r.adapter || o.scope.manager != r.manager || ctx.Value(wgOperationMaterialKey{}) != o.material || !o.material.RetainedOperationContext(ctx) || wgOperationCleanup(ctx) {
		return ErrWGOperationOwner
	}
	return nil
}

func (r *WGSourceReadReview) sourceCurrent(ctx context.Context, retained bool) error {
	if !retained {
		return r.Current(ctx)
	}
	if err := r.sourceCurrentPure(ctx, true); err != nil {
		return err
	}
	if err := r.control.Current(ctx); err != nil {
		return err
	}
	if err := r.tools.Runner.CheckWG(ctx, r.tools.Identity); err != nil {
		return err
	}
	return r.sourceCurrentPure(ctx, true)
}

type wgRetainedSourceRunner struct{ reader *WGSourceReadReview }

func (r wgRetainedSourceRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return r.reader.runSource(ctx, true, name, args...)
}

func (c *WGSourceProfileCapture) CurrentRetained(ctx context.Context) error {
	return c.sourceCurrent(ctx, true)
}
func (r *WGSourceReadReview) ObserveNumericEndpointRetained(ctx context.Context, c *WGSourceProfileCapture) (WGEndpointState, error) {
	return r.observeNumericEndpoint(ctx, c, true)
}
