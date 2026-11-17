package dataplane

import (
	"context"
	"errors"
)

func (r *WGInactivityRead) kernelEmptyTableAvailable() bool {
	if r == nil {
		return false
	}
	_, ok := r.tools.Runner.(wgKernelServiceTableSource)
	return ok
}

// Absence only, through the already-supported original kernel table source.
// Its two complete fresh route dumps do not grant interface/receipt ownership.
// Session exit and Close cancel and join this read exactly as for kernel links.
func (r *WGInactivityRead) readKernelEmptyTable(ctx context.Context, table, family int) error {
	if r == nil || r.self != r || !wgInactivityFinite(ctx) || family != 4 && family != 6 {
		return ErrWGOperationOwner
	}
	spec, err := r.shape.endpointSpec()
	if err != nil || table != spec.Table && table != spec.EndpointTable && table != 219 {
		return errors.Join(err, ErrWGOperationOwner)
	}
	s, _ := ctx.Value(wgInactivitySessionKey{}).(*wgInactivityReadSession)
	if s == nil || s.self != s || s.source != r {
		return ErrWGOperationOwner
	}
	s.mu.Lock()
	if !s.open || s.ctx == nil || s.ctx.Err() != nil {
		s.mu.Unlock()
		return ErrWGOperationOwner
	}
	s.reads.Add(1)
	s.mu.Unlock()
	defer s.reads.Done()
	deadline, _ := ctx.Deadline()
	c, cancel := context.WithDeadline(s.ctx, deadline)
	stop := context.AfterFunc(ctx, cancel)
	defer func() { stop(); cancel() }()
	return r.observeCleanupKernelTools(c, s, func(c context.Context) error {
		if err := errors.Join(r.current(c, s.cleanup), s.roots.current(c)); err != nil {
			return err
		}
		source, ok := r.tools.Runner.(wgKernelServiceTableSource)
		if !ok {
			return ErrWGOperationOwner
		}
		count, err := source.ReadWGKernelServiceTable(c, r.tools.Identity, table, family, r.shape.interfaceName())
		closing := errors.Join(r.current(c, s.cleanup), s.roots.current(c), c.Err())
		if err != nil || closing != nil || count != 0 {
			return errors.Join(err, closing, errWGInactiveUnknown)
		}
		return nil
	})
}
