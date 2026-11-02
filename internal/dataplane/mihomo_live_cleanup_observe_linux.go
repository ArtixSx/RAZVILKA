//go:build linux

package dataplane

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func observeMihomoLiveCleanupProcess(ctx context.Context, child *components.MihomoLiveProcess, cleanup *operationgate.ExclusiveCleanupReview, provider *netidentity.Provider, expected netidentity.Identity) (mihomoProbeObservation, error) {
	var result mihomoProbeObservation
	if provider == nil {
		return result, errMihomoProbeObservation
	}
	err := provider.WithCurrent(ctx, func(networkCtx context.Context, current netidentity.Identity) error {
		if current != expected {
			return errMihomoProbeObservation
		}
		return child.WithCleanupReadObservation(networkCtx, cleanup, func(held context.Context, view *components.MihomoLiveCleanupObservation) error {
			var err error
			result, err = observeMihomoLiveCleanupObservation(held, view, expected)
			return err
		})
	})
	if err != nil {
		return mihomoProbeObservation{}, err
	}
	return result, nil
}

func observeMihomoLiveCleanupObservation(ctx context.Context, view *components.MihomoLiveCleanupObservation, expected netidentity.Identity) (mihomoProbeObservation, error) {
	profile, err := view.ProfileReference(ctx)
	if err != nil {
		return mihomoProbeObservation{}, err
	}
	result, err := observeOriginalMihomoProcessInNetwork(ctx, view, components.MihomoProbeReference{SOCKSPort: profile.SOCKSPort, ConfigSHA256: profile.ConfigSHA256}, expected)
	if err != nil {
		return mihomoProbeObservation{}, err
	}
	closing, err := view.ProfileReference(ctx)
	if err != nil || closing != profile {
		return mihomoProbeObservation{}, errors.Join(errMihomoProbeObservation, err)
	}
	return result, nil
}
