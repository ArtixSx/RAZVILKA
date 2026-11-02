package dataplane

import (
	"bytes"
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// RetainedProxySidecarKind recognizes only this owner's generated sidecar
// images. It is read-only classification for config-less removal, not process,
// kernel ownership, start, cleanup or installed-binary authority.
func RetainedProxySidecarKind(ctx context.Context, id, stateRoot string) (string, error) {
	a, err := NewProxyTunnelAdapter(id, nil, stateRoot)
	if err != nil {
		return "", err
	}
	image, err := restorejournal.ReadFileImage(ctx, a.sidecarConfigPath())
	if err != nil {
		return "", err
	}
	if !image.Exists {
		return "", nil
	}
	if len(image.Data) > 128<<10 {
		return "", ErrProxyPolicyUnknown
	}
	hev, err := a.hevConfig()
	if err != nil {
		return "", err
	}
	if bytes.Equal(image.Data, hev) {
		return "hev", nil
	}
	for _, schema := range []singBoxSidecarSchema{{}, {modernAddress: true}, {modernAddress: true, dnsMode: true}} {
		candidate, err := buildSOCKSTunnelConfigForSchema(a.Interface, a.TunnelCIDR, a.SOCKSPort, schema)
		if err != nil {
			return "", err
		}
		if bytes.Equal(image.Data, candidate) {
			return "sing-box", nil
		}
	}
	return "", errors.Join(ErrProxyPolicyUnknown, errors.New("retained sidecar is not an exact owned backend image"))
}
