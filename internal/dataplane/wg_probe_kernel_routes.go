package dataplane

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type wgKernelServiceTableSource interface {
	ReadWGKernelServiceTable(context.Context, netidentity.Identity, int, int, string) (int, error)
}

// Same original material/operation barriers as the existing kernel link read.
// The query is bound to the retained adapter's numeric table/interface; the
// scalar cannot become an ownership/receipt or a successful mutation ACK.
func (r wgExecRunner) readProbeKernelServiceTable(ctx context.Context, family int) (int, error) {
	if ctx == nil || family != 4 && family != 6 {
		return 0, ErrWGOperationOwner
	}
	o, owned := ctx.Value(wgOperationOwnerKey{}).(*wgOperationOwner)
	m, material := ctx.Value(wgOperationMaterialKey{}).(*WGOperationMaterial)
	if !owned || !material || m == nil || o == nil || o.self != o || o.material != m || o.scope == nil || o.adapter != r.adapter {
		return 0, ErrWGOperationOwner
	}
	m.barrier.RLock()
	defer m.barrier.RUnlock()
	o.scope.startMu.RLock()
	defer o.scope.startMu.RUnlock()
	cleanup := wgOperationCleanup(ctx)
	if err := o.check(ctx, cleanup); err != nil {
		return 0, err
	}
	tools := o.adapter.wgCommandTools
	if !tools.valid(o.adapter.ID()) {
		return 0, ErrWGOperationOwner
	}
	source, ok := tools.Runner.(wgKernelServiceTableSource)
	if !ok {
		return 0, ErrWGOperationOwner
	}
	count, err := source.ReadWGKernelServiceTable(ctx, tools.Identity, o.adapter.table(), family, o.adapter.interfaceName())
	closing := errors.Join(o.check(ctx, cleanup), ctx.Err())
	if closing != nil && !cleanup {
		o.mu.Lock()
		o.revoked = errors.Join(o.revoked, closing)
		o.mu.Unlock()
	}
	if err != nil || closing != nil {
		return 0, errors.Join(err, closing)
	}
	if count != 0 && count != 1 {
		return 0, ErrWGNetworkPolicy
	}
	return count, nil
}
