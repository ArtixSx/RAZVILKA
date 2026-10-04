package app

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// Called under the owning operation admission after strict typed validation,
// before any incoming private material is persisted. Callback probes run with
// no Store lock held. Standalone legacy material retains reader1 compatibility.
func (a *App) nodeHistoryMaterialAdmission(ctx context.Context, required int) (err error) {
	defer func() {
		if recover() != nil {
			err = errNodeHistoryAdmission
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if required < 1 || required > nodestore.ExactHistoryReadVersion {
		return errNodeHistoryAdmission
	}
	if a.NodeHistoryWriteGuard == nil {
		if required != 1 {
			return errNodeHistoryAdmission
		}
		return ctx.Err()
	}
	if err := a.NodeHistoryWriteGuard(ctx, required); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errNodeHistoryAdmission
	}
	return ctx.Err()
}
