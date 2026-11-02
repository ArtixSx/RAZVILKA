//go:build linux

package dataplane

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Comparison only: same retained child and its own sealed profile, full kernel
// executable/FD/listener association and network bookends. No process can be
// reconstructed from the returned observation or a detached reference.
func observeMihomoLiveProcess(ctx context.Context, child *components.MihomoLiveProcess, provider *netidentity.Provider, expected netidentity.Identity) (mihomoProbeObservation, error) {
	var result mihomoProbeObservation
	err := child.WithReadObservation(ctx, func(held context.Context, view *components.MihomoLiveObservation) error {
		var err error
		result, err = observeMihomoLiveObservation(held, view, provider, expected)
		return err
	})
	if err != nil {
		return mihomoProbeObservation{}, err
	}
	return result, nil
}

func observeMihomoLiveObservation(ctx context.Context, view *components.MihomoLiveObservation, provider *netidentity.Provider, expected netidentity.Identity) (mihomoProbeObservation, error) {
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
