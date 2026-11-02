//go:build linux

package dataplane

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"os"
)

type mihomoLiveCleanupObservedChild struct {
	child   *components.MihomoLiveProcess
	cleanup *operationgate.ExclusiveCleanupReview
}

func (c *mihomoLiveCleanupObservedChild) Current(ctx context.Context) error {
	return c.child.CurrentForCleanup(ctx, c.cleanup)
}
func (c *mihomoLiveCleanupObservedChild) PID() int { return c.child.PID() }
func (c *mihomoLiveCleanupObservedChild) MatchesFile(kind string, info os.FileInfo) bool {
	return c.child.MatchesFile(kind, info)
}

func observeMihomoLiveCleanupProcess(ctx context.Context, child *components.MihomoLiveProcess, cleanup *operationgate.ExclusiveCleanupReview, provider *netidentity.Provider, expected netidentity.Identity) (mihomoProbeObservation, error) {
	profile, err := child.ProfileReferenceForCleanup(ctx, cleanup)
	if err != nil {
		return mihomoProbeObservation{}, err
	}
	owner := &mihomoLiveCleanupObservedChild{child: child, cleanup: cleanup}
	result, err := observeOriginalMihomoProcess(ctx, owner, components.MihomoProbeReference{SOCKSPort: profile.SOCKSPort, ConfigSHA256: profile.ConfigSHA256}, provider, expected)
	if err != nil {
		return mihomoProbeObservation{}, err
	}
	closing, err := child.ProfileReferenceForCleanup(ctx, cleanup)
	if err != nil || closing != profile {
		return mihomoProbeObservation{}, errors.Join(errMihomoProbeObservation, err)
	}
	return result, nil
}
