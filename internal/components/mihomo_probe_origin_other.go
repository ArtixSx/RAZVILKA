//go:build !linux

package components

import "context"

// Other platforms retain the legacy data-only reference. Native Run refuses.
func captureMihomoProbeOrigin(context.Context) (mihomoProbeOriginOwner, error) { return nil, nil }
func ObserveMihomoProbeParentGone(context.Context, MihomoProbeParentOrigin) error {
	return ErrMihomoProbeOrigin
}
