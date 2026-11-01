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
	profile, err := child.ProfileReference(ctx)
	if err != nil {
		return mihomoProbeObservation{}, err
	}
	result, err := observeOriginalMihomoProcess(ctx, child, components.MihomoProbeReference{SOCKSPort: profile.SOCKSPort, ConfigSHA256: profile.ConfigSHA256}, provider, expected)
	if err != nil {
		return mihomoProbeObservation{}, err
	}
	closing, err := child.ProfileReference(ctx)
	if err != nil || closing != profile {
		return mihomoProbeObservation{}, errors.Join(errMihomoProbeObservation, err)
	}
	return result, nil
}
