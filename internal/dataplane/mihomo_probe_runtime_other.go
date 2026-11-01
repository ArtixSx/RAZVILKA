//go:build !linux

package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func (r *mihomoProbeResource) run(context.Context) error   { return ErrMihomoProbe }
func (r *mihomoProbeResource) clean(context.Context) error { return ErrMihomoProbe }
func observeMihomoProbeListenerAbsent(context.Context, *netidentity.Provider, netidentity.Identity, int) error {
	return ErrMihomoProbe
}
