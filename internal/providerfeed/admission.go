package providerfeed

import (
	"context"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// syncAdmission belongs to one worker invocation. Managed downloads release
// application admission while performing bounded network work, then take a NEW
// lease before touching stores. The manager's single-download slot is retained.
type syncAdmission struct {
	enter func(context.Context) (func(), error)
	leave func()
}

// SyncWithAdmission is for an already-authorized server-owned workflow. The
// caller must NOT hold application admission. The method owns fresh leases
// around local stores only, and does not create a queue or detach from ctx.
func (m *Manager) SyncWithAdmission(ctx context.Context, request Request, enter func(context.Context) (func(), error)) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute+Timeout+5*time.Second)
	defer cancel()
	lease := &syncAdmission{enter: enter}
	if err := lease.acquire(ctx); err != nil {
		return Result{}, err
	}
	defer lease.release()
	return m.syncRequest(ctx, request, lease)
}

// SyncSavedWithAdmission has the same lifetime and admission contract, loading
// the source's current revision after its initial admission.
func (m *Manager) SyncSavedWithAdmission(ctx context.Context, id string, enter func(context.Context) (func(), error)) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute+Timeout+5*time.Second)
	defer cancel()
	lease := &syncAdmission{enter: enter}
	if err := lease.acquire(ctx); err != nil {
		return Result{}, err
	}
	defer lease.release()
	return m.syncSaved(ctx, id, lease)
}

func (a *syncAdmission) acquire(ctx context.Context) error {
	if a == nil || a.leave != nil {
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if a.enter == nil {
			a.leave = func() {}
			return nil
		}
		release, err := a.enter(ctx)
		if err == nil {
			a.leave = release
			return nil
		}
		if !errors.Is(err, operationgate.ErrBusy) {
			return err
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (a *syncAdmission) release() {
	if a != nil && a.leave != nil {
		a.leave()
		a.leave = nil
	}
}
