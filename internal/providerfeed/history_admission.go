package providerfeed

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func (m *Manager) checkHistoryWriteAdmission(ctx context.Context, required int) (err error) {
	if ctx == nil || m == nil || required < 1 || required > nodestore.ExactHistoryReadVersion {
		return ErrHistoryAdmission
	}
	// A callback must not leak its private executable/endpoint error text, panic
	// out of the worker, or return nil after canceling the original context.
	defer func() {
		if recover() != nil {
			err = ErrHistoryAdmission
		}
		if canceled := ctx.Err(); canceled != nil {
			err = canceled
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.HistoryWriteAdmission == nil {
		if required == 1 {
			return nil
		}
		return ErrHistoryAdmission
	}
	if m.HistoryWriteAdmission(ctx, required) != nil {
		return ErrHistoryAdmission
	}
	return nil
}
