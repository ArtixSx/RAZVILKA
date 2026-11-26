package app

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/config"
)

// Both public control and the explicit autonomy wizard use the same writer.
// An existing managed owner must accept its authentic mode-only transition
// before any worker is woken. Other saved settings retain their existing CAS.
func (a *App) updateServiceControlMode(ctx context.Context, mode *string, schedule *config.ServiceCheckSchedule, revision uint64) error {
	if handled, err := a.updateManagedXrayServiceMode(ctx, mode, schedule, revision); handled {
		if err != nil {
			return errors.Join(config.ErrRevisionChanged, err)
		}
		return err
	}
	return a.Store.UpdateServiceControl(mode, schedule, revision)
}
