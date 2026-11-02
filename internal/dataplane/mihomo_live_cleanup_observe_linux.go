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
	err := child.WithCleanupReadObservation(ctx, cleanup, func(held context.Context, view *components.MihomoLiveCleanupObservation) error {
		var err error
		result, err = observeMihomoLiveCleanupObservation(held, view, provider, expected)
		return err
	})
	if err != nil {
		return mihomoProbeObservation{}, err
	}
	return result, nil
}

func observeMihomoLiveCleanupObservation(ctx context.Context, view *components.MihomoLiveCleanupObservation, provider *netidentity.Provider, expected netidentity.Identity) (mihomoProbeObservation, error) {
	profile, err := view.ProfileReference(ctx)
	if err != nil {
		return mihomoProbeObservation{}, err
	}
	result, err := observeOriginalMihomoProcess(ctx, view, components.MihomoProbeReference{SOCKSPort: profile.SOCKSPort, ConfigSHA256: profile.ConfigSHA256}, provider, expected)
	if err != nil {
		return mihomoProbeObservation{}, err
	}
	closing, err := view.ProfileReference(ctx)
	if err != nil || closing != profile {
		return mihomoProbeObservation{}, errors.Join(errMihomoProbeObservation, err)
	}
	return result, nil
}
