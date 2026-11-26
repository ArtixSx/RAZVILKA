//go:build linux

package dataplane

import (
	"context"
	"errors"
	"io"
	"slices"

	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/probecheck"
)

func (r *mihomoLiveResource) canaryLive(ctx context.Context) error {
	if err := errors.Join(r.currentBeforeStart(ctx), r.nativeCurrent(ctx), r.liveEndpointsCurrent(ctx)); err != nil {
		return err
	}
	for _, probe := range mihomoRequiredProbes(r.definition.Service) {
		service := cloneXraySelectedTCPService(r.definition.Service)
		service.ProbeURL = probe.URL
		addresses, err := resolveNodeServiceIPv4(ctx, probe.URL, r.proxy.Resolver)
		if err != nil || len(addresses) == 0 {
			return errors.Join(ErrMihomoProbe, err)
		}
		for _, address := range addresses {
			if !nodeRouterPinInScope(address, r.definition.Policy.Prefixes) {
				return ErrNodeResourceDenied
			}
			if err = errors.Join(checkNodeResourceURL(ctx, probe.URL, address), r.nativeCurrent(ctx)); err != nil {
				return err
			}
			var chain []string
			response, closeTransport, err := socksHTTPGetPinnedObservedTLS(ctx, probe.URL, mihomoProbeEndpoint(r.definition.Profile.SOCKSPort).String(), address, nil, &service, &chain)
			if err != nil {
				return err
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, probecheck.MaxBodyBytes+1))
			closeErr := response.Body.Close()
			closeTransport()
			assessment := probecheck.Evaluate(service, probe, probecheck.Observation{RequestedURL: probe.URL, FinalURL: probecheck.FinalURL(response, probe.URL), RedirectChain: chain, HTTPStatus: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: body, BodyTruncated: len(body) > probecheck.MaxBodyBytes})
			clear(body)
			if readErr != nil || closeErr != nil || assessment.Verdict != evidence.VerdictPass {
				return errors.Join(ErrMihomoProbe, readErr, closeErr)
			}
			if err = errors.Join(checkNodeResourceURL(ctx, probe.URL, address), r.nativeCurrent(ctx), r.currentBeforeStart(ctx)); err != nil {
				return err
			}
		}
		closing, err := resolveNodeServiceIPv4(ctx, probe.URL, r.proxy.Resolver)
		if err != nil || !slices.Equal(addresses, closing) {
			return errors.Join(ErrNodeEndpointChanged, err)
		}
	}
	return errors.Join(r.currentBeforeStart(ctx), r.nativeCurrent(ctx), r.liveEndpointsCurrent(ctx))
}
